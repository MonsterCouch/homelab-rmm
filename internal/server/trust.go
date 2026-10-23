package server

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Trust bundles (docs/plans/2026-10-06-phase3-signed-actions.md, 3.4 and 4.1).
//
// The server proposes; it never decides. A new bundle becomes the
// organization's next epoch only when it carries what an agent holding the
// CURRENT bundle would demand (actionauth.VerifyUpdate: bundle_threshold
// distinct owners' assertions, or a recovery signature), so a compromised
// server cannot slip its own keys into the chain. The one exception is the
// FIRST bundle, which agents accept on first use: there the server only
// insists that a signer in the proposed bundle proves their key works, so a
// bundle that cannot be used is not pinned into the fleet.

const (
	proposalTTL          = 7 * 24 * time.Hour // recovery signing is done offline and may take a while
	maxOpenProposals     = 20
	trustPushTimeout     = 30 * time.Second
	defaultBulkLimit     = 10
	defaultTrustModeName = actionauth.ModeAudit
)

// ---- storage ----

type trustRow struct {
	OrgID       string
	Epoch       int64
	Bundle      []byte
	Hash        string
	Sigs        []protocol.Assertion
	RSigs       []protocol.RecoverySig
	ActivatedBy string
	ActivatedAt int64
}

type trustProposal struct {
	ID        string
	OrgID     string
	Epoch     int64
	Bundle    []byte
	Sigs      []protocol.Assertion
	RSigs     []protocol.RecoverySig
	CreatedBy string
	CreatedAt int64
	ExpiresAt int64
}

func scanTrustRow(row interface{ Scan(...any) error }) (*trustRow, error) {
	var t trustRow
	var sigs, rsigs string
	if err := row.Scan(&t.OrgID, &t.Epoch, &t.Bundle, &t.Hash, &sigs, &rsigs, &t.ActivatedBy, &t.ActivatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(sigs), &t.Sigs)
	json.Unmarshal([]byte(rsigs), &t.RSigs)
	return &t, nil
}

const trustCols = `org_id, epoch, bundle, hash, sigs, recovery_sigs, activated_by, activated_at`

// currentTrust is the organization's newest bundle, or nil when it has none.
func (d *DB) currentTrust(org string) (*trustRow, error) {
	t, err := scanTrustRow(d.QueryRow(`SELECT `+trustCols+` FROM trust_bundles WHERE org_id = ? ORDER BY epoch DESC LIMIT 1`, org))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (d *DB) trustAt(org string, epoch int64) (*trustRow, error) {
	t, err := scanTrustRow(d.QueryRow(`SELECT `+trustCols+` FROM trust_bundles WHERE org_id = ? AND epoch = ?`, org, epoch))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return t, err
}

// trustHashes maps each stored epoch to its bundle hash.
func (d *DB) trustHashes(org string) (map[int64]string, error) {
	rows, err := d.Query(`SELECT epoch, hash FROM trust_bundles WHERE org_id = ?`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var e int64
		var h string
		if err := rows.Scan(&e, &h); err != nil {
			return nil, err
		}
		out[e] = h
	}
	return out, rows.Err()
}

func scanProposal(row interface{ Scan(...any) error }) (*trustProposal, error) {
	var p trustProposal
	var sigs, rsigs string
	if err := row.Scan(&p.ID, &p.OrgID, &p.Epoch, &p.Bundle, &sigs, &rsigs, &p.CreatedBy, &p.CreatedAt, &p.ExpiresAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(sigs), &p.Sigs)
	json.Unmarshal([]byte(rsigs), &p.RSigs)
	return &p, nil
}

const proposalCols = `id, org_id, epoch, bundle, sigs, recovery_sigs, created_by, created_at, expires_at`

func (d *DB) loadProposal(id string) (*trustProposal, error) {
	p, err := scanProposal(d.QueryRow(`SELECT `+proposalCols+` FROM trust_proposals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.ExpiresAt < now() {
		d.Exec(`DELETE FROM trust_proposals WHERE id = ?`, id)
		return nil, errNotFound
	}
	return p, nil
}

func (d *DB) orgProposals(org string) ([]*trustProposal, error) {
	d.Exec(`DELETE FROM trust_proposals WHERE expires_at < ?`, now())
	rows, err := d.Query(`SELECT `+proposalCols+` FROM trust_proposals WHERE org_id = ? ORDER BY created_at`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*trustProposal
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) saveProposalSigs(p *trustProposal) error {
	_, err := d.Exec(`UPDATE trust_proposals SET sigs = ?, recovery_sigs = ? WHERE id = ?`, jsonText(nonNil(p.Sigs)), jsonText(nonNilR(p.RSigs)), p.ID)
	return err
}

func nonNil(a []protocol.Assertion) []protocol.Assertion {
	if a == nil {
		return []protocol.Assertion{}
	}
	return a
}

func nonNilR(a []protocol.RecoverySig) []protocol.RecoverySig {
	if a == nil {
		return []protocol.RecoverySig{}
	}
	return a
}

func (d *DB) orgExists(id string) bool {
	var one int
	return d.QueryRow(`SELECT 1 FROM organizations WHERE id = ?`, id).Scan(&one) == nil
}

// setAgentTrust records the bundle an agent says it holds.
func (d *DB) setAgentTrust(agentID string, epoch int64, hash string) {
	d.Exec(`UPDATE agents SET trust_epoch = ?, trust_hash = ? WHERE id = ?`, epoch, hash, agentID)
}

// ---- building a bundle ----

type trustSignerIn struct {
	Owner         string   `json:"owner"`
	CredentialIDs []string `json:"credential_ids"`
}

type trustRecoveryIn struct {
	ID  string `json:"id"`
	Pub string `json:"pub"`
}

// trustProposalIn describes the whole desired bundle, not a delta against the
// current one: what the operator sees in the console is what is signed.
type trustProposalIn struct {
	Mode            string          `json:"mode"`
	RequireUV       bool            `json:"require_uv"`
	HighThreshold   int             `json:"high_threshold"`
	BundleThreshold int             `json:"bundle_threshold"`
	BulkLimit       int             `json:"bulk_limit"`
	Signers         []trustSignerIn `json:"signers"`
	// Recovery lists keys to ADD. The console only ever holds the key it just
	// generated (the trust state exposes recovery IDs, not public keys), so
	// the current bundle's recovery keys are carried forward and a proposal
	// that merely omitted them would otherwise silently drop them and could
	// lock the organization out. RemoveRecoveryIDs retires keys on purpose.
	Recovery          []trustRecoveryIn `json:"recovery"`
	RemoveRecoveryIDs []string          `json:"remove_recovery_ids"`
}

// buildTrustBundle assembles the next epoch's canonical bytes and validates
// them with the same parser agents use, so whatever it returns an agent can
// load. Its errors are the operator's to fix (400s).
func (s *Server) buildTrustBundle(orgID string, in trustProposalIn, cur *trustRow) ([]byte, *actionauth.Bundle, error) {
	rpID, origins, err := s.webauthnRP()
	if err != nil {
		return nil, nil, err
	}
	b := actionauth.Bundle{V: 1, Epoch: 1, Org: orgID, RPID: rpID, Origins: origins, Policy: actionauth.Policy{
		Mode: in.Mode, RequireUV: in.RequireUV, HighThreshold: in.HighThreshold, BundleThreshold: in.BundleThreshold, BulkLimit: in.BulkLimit,
	}}
	if cur != nil {
		b.Epoch, b.Prev = cur.Epoch+1, cur.Hash
	}
	if b.Policy.Mode == "" {
		b.Policy.Mode = defaultTrustModeName
	}
	if b.Policy.HighThreshold == 0 {
		b.Policy.HighThreshold = 1
	}
	if b.Policy.BundleThreshold == 0 {
		b.Policy.BundleThreshold = 1
	}
	if b.Policy.BulkLimit == 0 {
		b.Policy.BulkLimit = defaultBulkLimit
	}
	for _, sg := range in.Signers {
		var uid int64
		var owner string
		if err := s.db.QueryRow(`SELECT id, username FROM users WHERE username = ?`, strings.TrimSpace(sg.Owner)).Scan(&uid, &owner); err != nil {
			return nil, nil, fmt.Errorf("signer %q is not a user", sg.Owner)
		}
		if len(sg.CredentialIDs) == 0 {
			return nil, nil, fmt.Errorf("signer %s needs at least one security key", owner)
		}
		signer := actionauth.Signer{Owner: owner}
		for _, cid := range sg.CredentialIDs {
			raw, err := b64dec(cid)
			if err != nil || len(raw) == 0 {
				return nil, nil, fmt.Errorf("credential id %q is not base64url", cid)
			}
			c, err := s.db.getCredential(actionauth.EncodeB64(raw))
			if err != nil || c.userID != uid {
				return nil, nil, fmt.Errorf("credential %s is not a registered key of %s", cid, owner)
			}
			signer.Creds = append(signer.Creds, actionauth.Credential{ID: c.ID, Alg: c.Alg, Pub: actionauth.EncodeB64(c.publicKey)})
		}
		b.Signers = append(b.Signers, signer)
	}
	removed := map[string]bool{}
	for _, id := range in.RemoveRecoveryIDs {
		removed[id] = true
	}
	have := map[string]string{}
	if cur != nil {
		curB, err := actionauth.ParseBundle(cur.Bundle)
		if err != nil {
			return nil, nil, fmt.Errorf("the bundle in force is unreadable: %w", err)
		}
		for _, rk := range curB.Recovery {
			if !removed[rk.ID] {
				b.Recovery = append(b.Recovery, rk)
				have[rk.ID] = rk.Pub
			}
		}
	}
	for _, id := range in.RemoveRecoveryIDs {
		if cur == nil {
			return nil, nil, fmt.Errorf("recovery key %q cannot be removed: there is no bundle in force", id)
		}
		if !curHasRecovery(cur, id) {
			return nil, nil, fmt.Errorf("recovery key %q is not in the bundle in force", id)
		}
	}
	for _, r := range in.Recovery {
		// The ID must be the one derived from the key: `rmm-server trust
		// sign-bundle` labels its signature with RecoveryKeyID(pub), so a key
		// filed under any other ID would accept no signature at all - a
		// recovery key that silently cannot recover.
		if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.Pub, "=")); err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("recovery key %q is not a base64url Ed25519 public key", r.ID)
		} else if want := actionauth.RecoveryKeyID(raw); r.ID != want {
			return nil, nil, fmt.Errorf("recovery key id %q does not match its public key (expected %q)", r.ID, want)
		}
		if pub, dup := have[r.ID]; dup {
			if pub != r.Pub {
				return nil, nil, fmt.Errorf("recovery key id %q is already used by a different key", r.ID)
			}
			continue // re-sent: already carried forward
		}
		have[r.ID] = r.Pub
		b.Recovery = append(b.Recovery, actionauth.RecoveryKey{ID: r.ID, Alg: "ed25519", Pub: r.Pub})
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, nil, err
	}
	canon, err := actionauth.CanonicalizeJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	nb, err := actionauth.ParseBundle(canon)
	if err != nil {
		return nil, nil, err
	}
	return canon, nb, nil
}

func curHasRecovery(cur *trustRow, id string) bool {
	b, err := actionauth.ParseBundle(cur.Bundle)
	if err != nil {
		return false
	}
	for _, rk := range b.Recovery {
		if rk.ID == id {
			return true
		}
	}
	return false
}

// ---- evaluating a proposal ----

// evaluateProposal says how many distinct owners have signed validly, how many
// are needed, and whether the proposal is now enough to activate. cur is the
// bundle in force (nil for the first bundle); prop is the proposal parsed.
func evaluateProposal(cur, prop *actionauth.Bundle, p *trustProposal) (have, need int, active bool) {
	if cur == nil {
		owners, _ := actionauth.Signers(p.Bundle, p.Sigs, prop)
		return len(owners), 1, len(owners) >= 1
	}
	owners, _ := actionauth.Signers(p.Bundle, p.Sigs, cur)
	_, err := actionauth.VerifyUpdate(cur, p.Bundle, p.Sigs, p.RSigs)
	return len(owners), cur.Policy.BundleThreshold, err == nil
}

// recoverySigError checks one recovery signature on its own so the operator
// is told why it was refused; VerifyUpdate only says the threshold was unmet.
func recoverySigError(cur *actionauth.Bundle, rs protocol.RecoverySig, raw []byte) error {
	sig, err := b64dec(rs.Sig)
	if err != nil {
		return errors.New("signature is not base64url")
	}
	for _, r := range cur.Recovery {
		if r.ID != rs.ID {
			continue
		}
		pub, err := b64dec(r.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return errors.New("the recovery key in the current bundle is unusable")
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
			return errors.New("recovery signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unknown recovery key %q", rs.ID)
}

// proposalContext loads what every proposal handler needs under the trust
// lock's protection: the proposal, the bundle in force and the parsed forms.
type proposalContext struct {
	p    *trustProposal
	cur  *actionauth.Bundle // nil: first bundle
	prop *actionauth.Bundle
}

// loadProposalContext answers the HTTP error itself (and returns false) when
// the proposal is gone or no longer the next epoch.
func (s *Server) loadProposalContext(w http.ResponseWriter, pid string) (*proposalContext, bool) {
	p, err := s.db.loadProposal(pid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "proposal not found or expired")
		return nil, false
	}
	row, err := s.db.currentTrust(p.OrgID)
	if err != nil {
		fail(w, err)
		return nil, false
	}
	want := int64(1)
	var cur *actionauth.Bundle
	if row != nil {
		want = row.Epoch + 1
		if cur, err = actionauth.ParseBundle(row.Bundle); err != nil {
			fail(w, fmt.Errorf("the stored bundle for epoch %d is unreadable: %w", row.Epoch, err))
			return nil, false
		}
	}
	if p.Epoch != want {
		writeErr(w, http.StatusConflict, fmt.Sprintf("this proposal is for epoch %d but the next epoch is %d; another bundle was activated first. Create a new proposal", p.Epoch, want))
		return nil, false
	}
	prop, err := actionauth.ParseBundle(p.Bundle)
	if err != nil {
		fail(w, err)
		return nil, false
	}
	return &proposalContext{p: p, cur: cur, prop: prop}, true
}

// ---- activation and distribution ----

// activateTrust stores the proposal as the organization's next epoch and
// pushes it to the agents that are online. The signatures that activated it
// are kept with it: they are what carries an agent that missed the epoch
// forward later.
func (s *Server) activateTrust(r *http.Request, c *proposalContext) error {
	p := c.p
	err := s.db.withTx(r.Context(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO trust_bundles(org_id, epoch, bundle, hash, sigs, recovery_sigs, activated_by, activated_at) VALUES(?,?,?,?,?,?,?,?)`,
			p.OrgID, p.Epoch, p.Bundle, c.prop.Hash(), jsonText(nonNil(p.Sigs)), jsonText(nonNilR(p.RSigs)), actor(r), now()); err != nil {
			return err
		}
		_, err := tx.Exec(`DELETE FROM trust_proposals WHERE org_id = ? AND epoch <= ?`, p.OrgID, p.Epoch)
		return err
	})
	if err != nil {
		return err
	}
	s.audit(r, "trust.activate", p.OrgID, map[string]any{"epoch": p.Epoch, "hash": c.prop.Hash(), "mode": c.prop.Mode(),
		"owners": c.prop.Owners(), "recovery": len(p.RSigs) > 0})
	s.pushTrust(p.OrgID)
	return nil
}

// pushTrust brings every online agent of the organization up to the current
// bundle. It goes through the same per-agent sync as a reconnect, so an agent
// that is several epochs behind is walked forward in order instead of being
// sent a bundle whose prev it cannot match.
func (s *Server) pushTrust(orgID string) {
	rows, err := s.db.Query(`SELECT id FROM agents WHERE org_id = ?`, orgID)
	if err != nil {
		slog.Warn("trust push: list agents", "org", orgID, "err", err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && s.hub.IsOnline(id) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		id := id
		s.goJob(func() { s.syncTrust(id) })
	}
}

// trustPlan is what a sync should do for one agent: replay Send epochs in
// order, or raise Alert (and send nothing).
type trustPlan struct {
	Send  []int64
	Alert string
}

// trustClass is where an agent's reported bundle stands against the
// organization's: "none", "current", "behind" (a known earlier epoch) or
// "mismatch" (an epoch the server never issued, or a different hash).
func trustClass(heldEpoch int64, heldHash string, curEpoch int64, hashes map[int64]string) string {
	switch {
	case curEpoch == 0 || heldEpoch == 0:
		return "none"
	case heldEpoch > curEpoch:
		return "mismatch"
	}
	if h, ok := hashes[heldEpoch]; !ok || !strings.EqualFold(h, heldHash) {
		return "mismatch"
	}
	if heldEpoch == curEpoch {
		return "current"
	}
	return "behind"
}

// planTrustSync is the decision half of bundle sync, kept free of I/O. An
// agent holding nothing gets the current bundle (trust on first use). One on
// a known earlier epoch is replayed forward. Anything else - a hash that is
// not the one we issued for that epoch, an epoch from the future - is not
// repaired, because pushing over a bundle the server did not issue is exactly
// what the agent must not be talked into; an operator looks at it instead.
func planTrustSync(heldEpoch int64, heldHash string, curEpoch int64, hashes map[int64]string) trustPlan {
	switch trustClass(heldEpoch, heldHash, curEpoch, hashes) {
	case "none":
		if curEpoch == 0 {
			return trustPlan{}
		}
		return trustPlan{Send: []int64{curEpoch}}
	case "current":
		return trustPlan{}
	case "behind":
		var send []int64
		for e := heldEpoch + 1; e <= curEpoch; e++ {
			send = append(send, e)
		}
		return trustPlan{Send: send}
	}
	if heldEpoch > curEpoch {
		return trustPlan{Alert: fmt.Sprintf("the device holds trust bundle epoch %d but the server's newest is epoch %d", heldEpoch, curEpoch)}
	}
	return trustPlan{Alert: fmt.Sprintf("the device's trust bundle for epoch %d (hash %s) is not the one this server issued for that epoch", heldEpoch, shortHash(heldHash))}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// syncTrust sends the agent whatever bundles it is missing. Callers run it
// on a goroutine; it never blocks the agent's read loop. A per-agent lock
// keeps a reconnect and an activation from replaying the same epoch twice,
// and the agent's epoch is read from the database under that lock so the
// second caller sees what the first achieved.
func (s *Server) syncTrust(agentID string) {
	lk, _ := s.trustSyncs.LoadOrStore(agentID, &sync.Mutex{})
	mu := lk.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	var org, hash string
	var held int64
	if err := s.db.QueryRow(`SELECT org_id, trust_epoch, trust_hash FROM agents WHERE id = ?`, agentID).Scan(&org, &held, &hash); err != nil {
		return
	}
	cur, err := s.db.currentTrust(org)
	if err != nil || cur == nil {
		return
	}
	hashes, err := s.db.trustHashes(org)
	if err != nil {
		return
	}
	plan := planTrustSync(held, hash, cur.Epoch, hashes)
	if plan.Alert != "" {
		s.alerts.trustMismatch(agentID, plan.Alert)
		return
	}
	for _, epoch := range plan.Send {
		row, err := s.db.trustAt(org, epoch)
		if err != nil {
			slog.Warn("trust sync: missing epoch", "agent", agentID, "epoch", epoch, "err", err)
			return
		}
		ctx, cancel := context.WithTimeout(s.jobContext(), trustPushTimeout)
		err = s.hub.Request(ctx, agentID, protocol.ReqTrustUpdate, protocol.TrustUpdate{
			Bundle: actionauth.EncodeB64(row.Bundle), S: row.Sigs, R: row.RSigs,
		}, nil)
		cancel()
		if err != nil {
			// Stop at the first failure: the next epoch's prev would not
			// match, and the agent's own reason is what the operator needs.
			slog.Warn("trust update not accepted", "agent", agentID, "epoch", epoch, "err", err)
			return
		}
		s.db.setAgentTrust(agentID, row.Epoch, row.Hash)
		slog.Info("trust bundle delivered", "agent", agentID, "org", org, "epoch", epoch)
	}
}

// ---- handlers ----

func proposalView(cur, prop *actionauth.Bundle, p *trustProposal) map[string]any {
	have, need, active := evaluateProposal(cur, prop, p)
	return map[string]any{
		"id": p.ID, "org_id": p.OrgID, "epoch": p.Epoch, "have": have, "need": need, "active": active,
		"created_by": p.CreatedBy, "created_at": p.CreatedAt, "expires_at": p.ExpiresAt,
	}
}

func (s *Server) handleCreateTrustProposal(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !s.db.orgExists(orgID) {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	var in trustProposalIn
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	cur, err := s.db.currentTrust(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	open, err := s.db.orgProposals(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	if len(open) >= maxOpenProposals {
		writeErr(w, http.StatusBadRequest, "too many open proposals for this organization; let some expire")
		return
	}
	raw, nb, err := s.buildTrustBundle(orgID, in, cur)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := &trustProposal{ID: "tp_" + randomHex(8), OrgID: orgID, Epoch: nb.Epoch, Bundle: raw,
		CreatedBy: actor(r), CreatedAt: now(), ExpiresAt: now() + int64(proposalTTL/time.Second)}
	if _, err := s.db.Exec(`INSERT INTO trust_proposals(id, org_id, epoch, bundle, sigs, recovery_sigs, created_by, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		p.ID, p.OrgID, p.Epoch, p.Bundle, "[]", "[]", p.CreatedBy, p.CreatedAt, p.ExpiresAt); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "trust.propose", orgID, map[string]any{"proposal": p.ID, "epoch": p.Epoch, "hash": nb.Hash(), "mode": nb.Mode()})
	var curB *actionauth.Bundle
	if cur != nil {
		curB, _ = actionauth.ParseBundle(cur.Bundle)
	}
	_, need, _ := evaluateProposal(curB, nb, p)
	writeJSON(w, 201, map[string]any{
		"id": p.ID, "epoch": p.Epoch, "bundle": actionauth.EncodeB64(raw), "hash": nb.Hash(),
		"need": need, "have": 0, "expires_at": p.ExpiresAt,
	})
}

func (s *Server) handleGetTrustProposal(w http.ResponseWriter, r *http.Request) {
	c, ok := s.loadProposalContext(w, r.PathValue("pid"))
	if !ok {
		return
	}
	v := proposalView(c.cur, c.prop, c.p)
	v["bundle"] = actionauth.EncodeB64(c.p.Bundle)
	v["hash"] = c.prop.Hash()
	v["mode"] = c.prop.Mode()
	against := c.cur
	if against == nil {
		against = c.prop
	}
	owners, _ := actionauth.Signers(c.p.Bundle, c.p.Sigs, against)
	v["signed_by"] = nonNilStrings(owners)
	rids := []string{}
	for _, rs := range c.p.RSigs {
		rids = append(rids, rs.ID)
	}
	v["recovery_signed"] = rids
	writeJSON(w, 200, v)
}

func nonNilStrings(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

func (s *Server) handleSignTrustProposal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Assertion protocol.Assertion `json:"assertion"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	c, ok := s.loadProposalContext(w, r.PathValue("pid"))
	if !ok {
		return
	}
	// Check the new assertion alone first, so a bad one is refused with its
	// reason instead of being stored and silently not counting. The signer
	// must be in the bundle in force; for the first bundle, in the proposal
	// itself, which proves the key works before agents pin it.
	against := c.cur
	if against == nil {
		against = c.prop
	}
	owners, errs := actionauth.Signers(c.p.Bundle, []protocol.Assertion{in.Assertion}, against)
	if len(owners) == 0 {
		msg := "assertion rejected"
		if len(errs) > 0 {
			msg += ": " + strings.Join(errs, "; ")
		}
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	cid := in.Assertion.Cred
	if raw, err := b64dec(cid); err == nil {
		cid = actionauth.EncodeB64(raw)
	}
	replaced := false
	for i, a := range c.p.Sigs { // one assertion per credential; a newer one replaces
		if ac, err := b64dec(a.Cred); err == nil && actionauth.EncodeB64(ac) == cid {
			c.p.Sigs[i], replaced = in.Assertion, true
		}
	}
	if !replaced {
		c.p.Sigs = append(c.p.Sigs, in.Assertion)
	}
	if err := s.db.saveProposalSigs(c.p); err != nil {
		fail(w, err)
		return
	}
	s.db.Exec(`UPDATE webauthn_credentials SET last_used_at = ? WHERE id = ?`, now(), cid)
	s.audit(r, "trust.sign", c.p.OrgID, map[string]any{"proposal": c.p.ID, "epoch": c.p.Epoch, "signer": owners[0]})

	have, need, active := evaluateProposal(c.cur, c.prop, c.p)
	if active {
		if err := s.activateTrust(r, c); err != nil {
			fail(w, err)
			return
		}
	}
	writeJSON(w, 200, map[string]any{"have": have, "need": need, "active": active})
}

func (s *Server) handleRecoverTrustProposal(w http.ResponseWriter, r *http.Request) {
	var in protocol.RecoverySig
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	c, ok := s.loadProposalContext(w, r.PathValue("pid"))
	if !ok {
		return
	}
	if c.cur == nil {
		writeErr(w, http.StatusBadRequest, "recovery keys only authorize a replacement of a bundle that is already in force")
		return
	}
	if err := recoverySigError(c.cur, in, c.p.Bundle); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	replaced := false
	for i, rs := range c.p.RSigs {
		if rs.ID == in.ID {
			c.p.RSigs[i], replaced = in, true
		}
	}
	if !replaced {
		c.p.RSigs = append(c.p.RSigs, in)
	}
	if err := s.db.saveProposalSigs(c.p); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "trust.recovery_sign", c.p.OrgID, map[string]any{"proposal": c.p.ID, "epoch": c.p.Epoch, "recovery_key": in.ID})
	have, need, active := evaluateProposal(c.cur, c.prop, c.p)
	if active {
		if err := s.activateTrust(r, c); err != nil {
			fail(w, err)
			return
		}
	}
	writeJSON(w, 200, map[string]any{"have": have, "need": need, "active": active})
}

func (s *Server) handleGetOrgTrust(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !s.db.orgExists(orgID) {
		writeErr(w, http.StatusNotFound, "organization not found")
		return
	}
	row, err := s.db.currentTrust(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	var cur *actionauth.Bundle
	var current any
	curEpoch := int64(0)
	if row != nil {
		if cur, err = actionauth.ParseBundle(row.Bundle); err != nil {
			fail(w, err)
			return
		}
		curEpoch = row.Epoch
		rids := []string{}
		for _, rk := range cur.Recovery {
			rids = append(rids, rk.ID)
		}
		current = map[string]any{
			"epoch": row.Epoch, "hash": row.Hash, "mode": cur.Mode(), "policy": cur.Policy,
			"signers": cur.Signers, "recovery_ids": rids, "rp_id": cur.RPID, "origins": cur.Origins,
			"activated_by": row.ActivatedBy, "activated_at": row.ActivatedAt,
		}
	}

	props, err := s.db.orgProposals(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	views := []map[string]any{}
	for _, p := range props {
		prop, err := actionauth.ParseBundle(p.Bundle)
		if err != nil {
			continue
		}
		v := proposalView(cur, prop, p)
		v["stale"] = p.Epoch != curEpoch+1
		views = append(views, v)
	}

	hashes, err := s.db.trustHashes(orgID)
	if err != nil {
		fail(w, err)
		return
	}
	counts := map[string]int{"at_current": 0, "behind": 0, "mismatched": 0, "none": 0}
	rows, err := s.db.Query(`SELECT trust_epoch, trust_hash FROM agents WHERE org_id = ?`, orgID)
	if err != nil {
		fail(w, err)
		return
	}
	for rows.Next() {
		var e int64
		var h string
		if rows.Scan(&e, &h) != nil {
			continue
		}
		switch trustClass(e, h, curEpoch, hashes) {
		case "current":
			counts["at_current"]++
		case "behind":
			counts["behind"]++
		case "mismatch":
			counts["mismatched"]++
		default:
			counts["none"]++
		}
	}
	rows.Close()
	writeJSON(w, 200, map[string]any{"current": current, "proposals": views, "agents": counts})
}
