package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// The 428 flow (docs/plans/2026-10-06-phase3-signed-actions.md, 4.1).
//
// A protected handler works out what it WOULD send (op, targets, payload)
// and hands it to runSigned instead of sending it. In an organization whose
// trust bundle is off or absent, that sends it exactly as before. Otherwise
// the server builds a manifest, keeps it (in memory, bound to the requesting
// user), and answers 428; the console has the operator's key sign the
// manifest and repeats the SAME request with X-Action-Auth. The retry is only
// a claim that the operator signed: what is dispatched is the stored manifest,
// and the retry must still describe the same action or it is refused.

const (
	actionManifestTTL  = 5 * time.Minute
	multiSignManifest  = 10 * time.Minute // the ceiling for an action; more approvers need longer
	grantTTL           = 15 * time.Minute
	standingTTL        = 180 * 24 * time.Hour
	standingPendingTTL = time.Hour // how long a half-signed standing approval stays open
	maxPendingPerUser  = 200
	headerActionAuth   = "X-Action-Auth"
)

// signedAction describes one protected request.
type signedAction struct {
	Kind        string // actionauth.KindAction (default), KindGrant or KindStanding
	Org         string // derived from Targets (agent IDs) when empty
	Op          string
	Ops         []string // grant
	Targets     []string
	Payload     any                     // action: what the agent will execute
	Constraints *actionauth.Constraints // standing
	Summary     string
	TTL         time.Duration
	// Run dispatches the action and writes the handler's normal response.
	// auth is nil when nothing is signed (no bundle, mode off, or an audit
	// mode skip). It may run later, on the request of whoever adds the last
	// signature, so it must capture what it needs from the original request
	// instead of reading r again (r carries the requester's identity).
	Run func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth)
}

type pendingManifest struct {
	id          string
	org         string
	user        *User
	from        string // where user asked from: what the action's own audit entry names
	kind        string
	op          string
	ops         []string
	targets     []string
	fingerprint string
	manifest    []byte
	summary     string
	createdAt   int64
	expiresAt   int64 // when this entry is dropped (the manifest may live longer)
	sigs        []protocol.Assertion
	done        bool
	// logIndex is the leaf the released manifest has in the transparency log;
	// logged says it was set (index 0 is a real leaf).
	logIndex int64
	logged   bool
	run      func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth)
}

type cachedGrant struct {
	ops  []string
	auth *protocol.ActionAuth
	exp  int64
}

type grantKey struct {
	user  int64
	agent string
}

// signingState is the in-memory half of the flow: manifests waiting for a
// signature and the grants operators hold. A restart costs one more click.
type signingState struct {
	mu      sync.Mutex
	pending map[string]*pendingManifest
	grants  map[grantKey][]cachedGrant
	staged  map[string]*stagedUpload // uploads staged on an agent, awaiting a signed fs.commit
}

func (st *signingState) sweepLocked() {
	t := now()
	for id, u := range st.staged {
		if u.expiresAt <= t {
			delete(st.staged, id)
		}
	}
	for id, p := range st.pending {
		if p.expiresAt <= t {
			delete(st.pending, id)
		}
	}
	for k, gs := range st.grants {
		kept := gs[:0]
		for _, g := range gs {
			if g.exp > t {
				kept = append(kept, g)
			}
		}
		if len(kept) == 0 {
			delete(st.grants, k)
		} else {
			st.grants[k] = kept
		}
	}
}

func (st *signingState) putGrant(user int64, agent string, ops []string, auth *protocol.ActionAuth, exp int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.grants == nil {
		st.grants = map[grantKey][]cachedGrant{}
	}
	st.sweepLocked()
	k := grantKey{user, agent}
	kept := st.grants[k][:0]
	for _, g := range st.grants[k] {
		if !slices.Equal(g.ops, ops) {
			kept = append(kept, g)
		}
	}
	st.grants[k] = append(kept, cachedGrant{ops: ops, auth: auth, exp: exp})
}

// grantFor returns a cached grant that covers op and has a little life left.
func (st *signingState) grantFor(user int64, agent, op string) *protocol.ActionAuth {
	st.mu.Lock()
	defer st.mu.Unlock()
	var best *cachedGrant
	for i := range st.grants[grantKey{user, agent}] {
		g := &st.grants[grantKey{user, agent}][i]
		if g.exp > now()+5 && slices.Contains(g.ops, op) && (best == nil || g.exp > best.exp) {
			best = g
		}
	}
	if best == nil {
		return nil
	}
	return best.auth
}

// ---- helpers ----

// activeBundle is the organization's current bundle, or nil when it has none
// or its mode is off: in both cases requests go out unsigned, as before.
func (s *Server) activeBundle(org string) *actionauth.Bundle {
	if org == "" {
		return nil
	}
	row, err := s.db.currentTrust(org)
	if err != nil || row == nil {
		return nil
	}
	b, err := actionauth.ParseBundle(row.Bundle)
	if err != nil || b.Mode() == actionauth.ModeOff {
		return nil
	}
	return b
}

var errMixedOrgs = errors.New("these devices belong to different organizations")

// orgOfAgents is the single organization the agents share.
func (s *Server) orgOfAgents(ids []string) (string, error) {
	org := ""
	for i, id := range ids {
		var o string
		if err := s.db.QueryRow(`SELECT org_id FROM agents WHERE id = ?`, id).Scan(&o); err != nil {
			return "", fmt.Errorf("agent %s: %w", id, errNotFound)
		}
		if i == 0 {
			org = o
		} else if o != org {
			return "", errMixedOrgs
		}
	}
	return org, nil
}

// agentOrgID is an agent's organization ("" when unknown).
func (s *Server) agentOrgID(id string) string {
	var o string
	s.db.QueryRow(`SELECT org_id FROM agents WHERE id = ?`, id).Scan(&o)
	return o
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return slices.Compact(out)
}

func canonicalOf(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	raw, ok := v.(json.RawMessage)
	if !ok {
		var err error
		if raw, err = json.Marshal(v); err != nil {
			return nil, err
		}
	}
	return actionauth.CanonicalizeJSON(raw)
}

func randomNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return actionauth.EncodeB64(b)
}

// needSigners is how many distinct owners must sign: the same rule the agent
// applies (a high-risk operation, or a manifest reaching more than bulk_limit
// agents, needs high_threshold).
func needSigners(b *actionauth.Bundle, kind, op string, ops []string, targets []string) int {
	check := op
	if kind == actionauth.KindGrant && len(ops) > 0 {
		check = ops[0]
	}
	if actionauth.ClassOf(check) == actionauth.ClassHighRisk || len(targets) > b.Policy.BulkLimit || slices.Contains(targets, "*") {
		return max(1, b.Policy.HighThreshold)
	}
	return 1
}

func (a *signedAction) fingerprint() (string, []byte, error) {
	payload, err := canonicalOf(a.Payload)
	if err != nil {
		return "", nil, err
	}
	var cons []byte
	if a.Constraints != nil {
		if cons, err = canonicalOf(a.Constraints); err != nil {
			return "", nil, err
		}
	}
	fp := strings.Join([]string{a.Kind, a.Op, strings.Join(sortedCopy(a.Ops), ","), strings.Join(a.Targets, ","), string(payload), string(cons)}, "\x00")
	return fp, payload, nil
}

func ownerCredentialIDs(b *actionauth.Bundle, owner string) []string {
	out := []string{}
	for _, sg := range b.Signers {
		if sg.Owner == owner {
			for _, c := range sg.Creds {
				out = append(out, c.ID)
			}
		}
	}
	return out
}

// issuerAddrKey marks, on a request that runs a signed action, the address the
// operator asked for the action from.
type issuerAddrKey struct{}

// withIssuer makes r speak for the operator who asked for the action: the
// pending entry's user, and the address they asked from. The closure that runs
// the action is reached by whoever adds the last signature, in an organization
// with several signers another operator at another address, and what it audits
// must name the one who asked.
func withIssuer(r *http.Request, p *pendingManifest) *http.Request {
	ctx := r.Context()
	if p.user != nil {
		ctx = context.WithValue(ctx, userKey, p.user)
	}
	if p.from != "" {
		ctx = context.WithValue(ctx, issuerAddrKey{}, p.from)
	}
	return r.WithContext(ctx)
}

func describeAuthHeader(h string) (id string, a protocol.Assertion, err error) {
	raw, derr := base64.RawURLEncoding.DecodeString(strings.TrimRight(h, "="))
	if derr != nil {
		return "", a, errors.New("X-Action-Auth is not base64url")
	}
	var in struct {
		ManifestID string             `json:"manifest_id"`
		Assertion  protocol.Assertion `json:"assertion"`
	}
	if err := json.Unmarshal(raw, &in); err != nil || in.ManifestID == "" {
		return "", a, errors.New("X-Action-Auth must be base64url of {manifest_id, assertion}")
	}
	return in.ManifestID, in.Assertion, nil
}

// addAssertion keeps one assertion per credential; a newer one replaces.
func addAssertion(sigs []protocol.Assertion, a protocol.Assertion) []protocol.Assertion {
	cid := a.Cred
	if raw, err := b64dec(cid); err == nil {
		cid = actionauth.EncodeB64(raw)
	}
	for i, x := range sigs {
		if xc, err := b64dec(x.Cred); err == nil && actionauth.EncodeB64(xc) == cid {
			sigs[i] = a
			return sigs
		}
	}
	return append(sigs, a)
}

// ---- the flow ----

// runSigned is the one helper every protected handler goes through.
func (s *Server) runSigned(w http.ResponseWriter, r *http.Request, sa signedAction) {
	if sa.Kind == "" {
		sa.Kind = actionauth.KindAction
	}
	sa.Targets = sortedCopy(sa.Targets)
	if sa.Org == "" && sa.Kind != actionauth.KindStanding {
		org, err := s.orgOfAgents(sa.Targets)
		if errors.Is(err, errMixedOrgs) {
			// One manifest names one organization. Unsigned organizations
			// would still go out as they always did, but a mixed set that
			// includes a protected one cannot be signed as a whole.
			for _, id := range sa.Targets {
				if s.activeBundle(s.agentOrgID(id)) != nil {
					writeErr(w, http.StatusBadRequest, "this request reaches devices of several organizations and at least one signs its actions; send it to one organization at a time")
					return
				}
			}
			sa.Run(w, r, nil)
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		sa.Org = org
	}
	b := s.activeBundle(sa.Org)
	if b == nil {
		sa.Run(w, r, nil)
		return
	}
	u := userFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	fp, payload, err := sa.fingerprint()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "this request cannot be signed: "+err.Error())
		return
	}
	enforce := b.Mode() == actionauth.ModeEnforce
	hdr := strings.TrimSpace(r.Header.Get(headerActionAuth))

	switch {
	case hdr == "":
		s.challenge(w, r, u, b, &sa, fp, payload, enforce)
	case strings.EqualFold(hdr, "skip"):
		if sa.Kind == actionauth.KindStanding {
			writeErr(w, http.StatusBadRequest, "an approval cannot be skipped")
			return
		}
		if enforce {
			writeErr(w, http.StatusForbidden, "signature required: this organization enforces signed actions, so the action was not sent")
			return
		}
		s.audit(r, "action.unsigned", sa.Org, map[string]any{"op": sa.Op, "ops": sa.Ops, "targets": sa.Targets, "mode": b.Mode()})
		sa.Run(w, r, nil)
	default:
		s.countersign(w, r, u, b, &sa, fp, hdr)
	}
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, u *User, b *actionauth.Bundle, sa *signedAction, fp string, payload []byte, enforce bool) {
	required := enforce || sa.Kind == actionauth.KindStanding
	creds := ownerCredentialIDs(b, u.Username)
	if len(creds) == 0 && required {
		writeErr(w, http.StatusForbidden, "signature required: you are not a signer in this organization's trust bundle; ask an administrator to add your security key")
		return
	}
	need := needSigners(b, sa.Kind, sa.Op, sa.Ops, sa.Targets)
	ttl := sa.TTL
	if ttl == 0 {
		ttl = actionManifestTTL
		if need > 1 {
			ttl = multiSignManifest
		}
	}
	t := now()
	m := actionauth.Manifest{
		V: 1, Kind: sa.Kind, ID: strings.ToUpper(randomHex(13)), Org: sa.Org, Targets: sa.Targets,
		Nonce: randomNonce(), IAT: t, Exp: t + int64(ttl/time.Second), Issuer: u.Username,
	}
	switch sa.Kind {
	case actionauth.KindAction:
		m.Op, m.Payload = sa.Op, payload
	case actionauth.KindGrant:
		m.Ops = sortedCopy(sa.Ops)
	case actionauth.KindStanding:
		m.Constraints = sa.Constraints
	}
	raw, err := actionauth.BuildManifest(m)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "this request cannot be signed: "+err.Error())
		return
	}
	p := &pendingManifest{
		id: m.ID, org: sa.Org, user: u, from: s.clientIP(r), kind: sa.Kind, op: sa.Op, ops: m.Ops, targets: sa.Targets, fingerprint: fp,
		manifest: raw, summary: sa.Summary, createdAt: t, expiresAt: m.Exp, run: sa.Run,
	}
	if sa.Kind == actionauth.KindStanding && p.expiresAt > t+int64(standingPendingTTL/time.Second) {
		p.expiresAt = t + int64(standingPendingTTL/time.Second)
	}
	st := &s.signing
	st.mu.Lock()
	if st.pending == nil {
		st.pending = map[string]*pendingManifest{}
	}
	st.sweepLocked()
	mine := 0
	for _, o := range st.pending {
		if o.user.ID == u.ID {
			mine++
		}
	}
	if mine >= maxPendingPerUser {
		st.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many unsigned requests are waiting; sign or let them expire")
		return
	}
	st.pending[p.id] = p
	st.mu.Unlock()

	uv := "preferred"
	if b.Policy.RequireUV {
		uv = "required"
	}
	writeJSON(w, http.StatusPreconditionRequired, map[string]any{
		"error":             "signature required: sign this action with your security key",
		"manifest_id":       p.id,
		"manifest":          actionauth.EncodeB64(raw),
		"summary":           sa.Summary,
		"required":          required,
		"rp_id":             b.RPID,
		"allow_credentials": creds,
		"user_verification": uv,
		"expires_at":        m.Exp,
	})
}

// takePending finds a live pending manifest. Unknown, expired and finished
// manifests all read the same way, so a manifest ID proves nothing.
func (s *Server) takePending(id string) *pendingManifest {
	st := &s.signing
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()
	p := st.pending[id]
	if p == nil || p.done {
		return nil
	}
	return p
}

// verifyAndAdd checks one assertion against the manifest and the bundle in
// force, stores it, and reports where the manifest stands. When it returns
// complete the caller must dispatch (the manifest is already claimed).
func (s *Server) verifyAndAdd(p *pendingManifest, a protocol.Assertion, r *http.Request) (have, need int, owner string, complete bool, status int, msg string) {
	b := s.activeBundle(p.org)
	if b == nil {
		return 0, 0, "", false, http.StatusConflict, "this organization no longer signs actions; repeat the request"
	}
	owners, errs := actionauth.Signers(p.manifest, []protocol.Assertion{a}, b)
	if len(owners) == 0 {
		m := "assertion rejected"
		if len(errs) > 0 {
			m += ": " + strings.Join(errs, "; ")
		}
		return 0, 0, "", false, http.StatusBadRequest, m
	}
	st := &s.signing
	st.mu.Lock()
	defer st.mu.Unlock()
	if p.done || st.pending[p.id] != p {
		return 0, 0, "", false, http.StatusGone, "this request is no longer waiting for signatures"
	}
	p.sigs = addAssertion(p.sigs, a)
	all, _ := actionauth.Signers(p.manifest, p.sigs, b)
	need = needSigners(b, p.kind, p.op, p.ops, p.targets)
	if len(all) >= need {
		p.done = true
		delete(st.pending, p.id)
		return len(all), need, owners[0], true, 0, ""
	}
	return len(all), need, owners[0], false, 0, ""
}

func (s *Server) noteSigned(r *http.Request, p *pendingManifest, a protocol.Assertion, owner string, have, need int) {
	cid := a.Cred
	if raw, err := b64dec(cid); err == nil {
		cid = actionauth.EncodeB64(raw)
	}
	s.db.Exec(`UPDATE webauthn_credentials SET last_used_at = ? WHERE id = ?`, now(), cid)
	s.audit(r, "action.sign", p.org, map[string]any{"manifest": p.id, "kind": p.kind, "op": p.op, "ops": p.ops, "targets": len(p.targets), "signer": owner, "have": have, "need": need})
}

// auth is the ActionAuth the device receives. When the manifest was logged at
// release it names its leaf; the hub fills in the proof for each send.
func (p *pendingManifest) auth() *protocol.ActionAuth {
	a := &protocol.ActionAuth{M: actionauth.EncodeB64(p.manifest), S: slices.Clone(p.sigs)}
	if p.logged {
		a.L = &protocol.LogProof{Index: p.logIndex}
	}
	return a
}

// release logs the finished manifest, once, and returns what to send. It is
// the one place both dispatch sites pass through before p.auth(). A log that
// cannot take the entry stops the dispatch: running a signed action that no
// one can later prove was relayed is the thing the log exists to prevent.
func (s *Server) release(w http.ResponseWriter, p *pendingManifest) (*protocol.ActionAuth, bool) {
	if s.tlog != nil && !p.logged {
		leaf, err := actionauth.ManifestLeaf(&protocol.ActionAuth{M: actionauth.EncodeB64(p.manifest), S: slices.Clone(p.sigs)})
		var idx int64
		if err == nil {
			idx, err = s.tlog.Append("manifest", leaf)
		}
		if err != nil {
			slog.Error("manifest was not added to the transparency log", "manifest", p.id, "err", err)
			writeErr(w, http.StatusInternalServerError, "the transparency log could not record this action, so nothing was sent; try again, and check the server log if it keeps failing")
			return nil, false
		}
		p.logIndex, p.logged = idx, true
	}
	return p.auth(), true
}

func pendingBody(p *pendingManifest, have, need int) map[string]any {
	return map[string]any{"pending": true, "manifest_id": p.id, "have": have, "need": need, "active": false}
}

// countersign handles the retried request: the operator's own signature.
func (s *Server) countersign(w http.ResponseWriter, r *http.Request, u *User, b *actionauth.Bundle, sa *signedAction, fp, hdr string) {
	id, a, err := describeAuthHeader(hdr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := s.takePending(id)
	if p == nil || p.user.ID != u.ID {
		writeErr(w, http.StatusGone, "this signing request is unknown or has expired; repeat the action to get a new one")
		return
	}
	if p.org != sa.Org || p.fingerprint != fp {
		writeErr(w, http.StatusConflict, "this request no longer matches what was signed (devices, content or options changed); repeat the action to sign it again")
		return
	}
	have, need, owner, complete, status, msg := s.verifyAndAdd(p, a, r)
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	s.noteSigned(r, p, a, owner, have, need)
	if !complete {
		writeJSON(w, http.StatusAccepted, pendingBody(p, have, need))
		return
	}
	// The stored closure carries this request's own parameters, but dispatch
	// what was signed: the pending entry's closure, not a fresh one.
	auth, ok := s.release(w, p)
	if !ok {
		return
	}
	p.run(w, withIssuer(r, p), auth)
}

// ---- approvals queue ----

// approvalEntry is one waiting manifest as the caller may see it, or false
// when it is not theirs to sign. Other people's entries appear once someone has
// signed them (before that only the operator who asked can know the id), the
// caller's own appear from the start so a challenge chosen for out-of-band
// signing is reachable, and an entry the caller already signed, or that has all
// the signatures it needs, is not waiting for them.
func (s *Server) approvalEntry(u *User, p *pendingManifest, bundles map[string]*actionauth.Bundle) (map[string]any, bool) {
	st := &s.signing
	st.mu.Lock()
	done := p.done
	sigs := slices.Clone(p.sigs)
	st.mu.Unlock()
	if done || p.expiresAt <= now() || !s.canAccessAgent(u, p.org) {
		return nil, false
	}
	if len(sigs) == 0 && (p.user == nil || p.user.ID != u.ID) {
		return nil, false
	}
	b, ok := bundles[p.org]
	if !ok {
		b = s.activeBundle(p.org)
		bundles[p.org] = b
	}
	if b == nil {
		return nil, false
	}
	owners, _ := actionauth.Signers(p.manifest, sigs, b)
	need := needSigners(b, p.kind, p.op, p.ops, p.targets)
	if len(owners) >= need || slices.Contains(owners, u.Username) {
		return nil, false
	}
	// Names are a convenience for the screen reading them, limited to devices
	// the caller may reach; what is signed is the ids in the manifest.
	names := map[string]string{}
	for _, id := range p.targets {
		if id == "*" || !s.canAccessAgent(u, s.agentOrgID(id)) {
			continue
		}
		if a, err := s.db.GetAgent(id); err == nil && a != nil {
			names[id] = agentLabel(a)
		}
	}
	uv := "preferred"
	if b.Policy.RequireUV {
		uv = "required"
	}
	issuer := ""
	if p.user != nil {
		issuer = p.user.Username
	}
	return map[string]any{
		"manifest_id": p.id, "manifest": actionauth.EncodeB64(p.manifest), "summary": p.summary,
		"have": len(owners), "need": need, "created_by": issuer, "issuer": issuer,
		"org": p.org, "created_at": p.createdAt, "expires_at": p.expiresAt,
		"kind": p.kind, "op": p.op, "ops": strs(p.ops), "targets": strs(p.targets), "target_names": names,
		"rp_id": b.RPID, "origins": strs(b.Origins), "allow_credentials": ownerCredentialIDs(b, u.Username),
		"user_verification": uv, "signers": strs(owners),
	}, true
}

func strs(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	st := &s.signing
	st.mu.Lock()
	st.sweepLocked()
	var list []*pendingManifest
	for _, p := range st.pending {
		list = append(list, p)
	}
	st.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].createdAt < list[j].createdAt })
	out := []map[string]any{}
	bundles := map[string]*actionauth.Bundle{}
	for _, p := range list {
		if e, ok := s.approvalEntry(u, p, bundles); ok {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetApproval answers one entry in the shape of the list, so a signer
// program given an id needs no listing. Anything the caller may not sign is a
// 404 whatever the reason, so ids do not leak across organizations.
func (s *Server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if p := s.takePending(r.PathValue("manifest_id")); p != nil {
		if e, ok := s.approvalEntry(u, p, map[string]*actionauth.Bundle{}); ok {
			writeJSON(w, http.StatusOK, e)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "no signing request with this id is waiting for your signature; it may have expired, been completed, or already carry your signature")
}

func (s *Server) handleSignApproval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Assertion protocol.Assertion `json:"assertion"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	u := userFrom(r.Context())
	p := s.takePending(r.PathValue("manifest_id"))
	if p == nil || !s.canAccessAgent(u, p.org) {
		writeErr(w, http.StatusGone, "this signing request is unknown or has expired")
		return
	}
	have, need, owner, complete, status, msg := s.verifyAndAdd(p, in.Assertion, r)
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	s.noteSigned(r, p, in.Assertion, owner, have, need)
	if !complete {
		writeJSON(w, http.StatusAccepted, pendingBody(p, have, need))
		return
	}
	auth, ok := s.release(w, p)
	if !ok {
		return
	}
	p.run(w, withIssuer(r, p), auth)
}

// ---- grants ----

func (s *Server) handleGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in struct {
		Ops []string `json:"ops"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ops := sortedCopy(in.Ops)
	if len(ops) == 0 {
		writeErr(w, http.StatusBadRequest, "ops required")
		return
	}
	for _, op := range ops {
		if actionauth.ClassOf(op) != actionauth.ClassGrant {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q cannot be granted: only shell.open, desktop.start, fs.list and fs.read are", op))
			return
		}
	}
	u := userFrom(r.Context())
	name := a.DisplayName
	if name == "" {
		name = a.Hostname
	}
	s.runSigned(w, r, signedAction{
		Kind: actionauth.KindGrant, Org: a.OrgID, Ops: ops, Targets: []string{id}, TTL: grantTTL,
		Summary: fmt.Sprintf("Allow %s on %s for 15 minutes: %s", u.Username, name, describeOps(ops)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			if auth == nil {
				writeJSON(w, http.StatusOK, map[string]any{"required": false})
				return
			}
			m, err := actionauth.ParseManifest(mustDecodeB64(auth.M))
			if err != nil {
				fail(w, err)
				return
			}
			who := userFrom(r.Context())
			s.signing.putGrant(who.ID, id, ops, auth, m.Exp)
			s.audit(r, "grant.open", id, map[string]any{"ops": ops, "expires_at": m.Exp})
			writeJSON(w, http.StatusOK, map[string]any{"expires_at": m.Exp})
		},
	})
}

func describeOps(ops []string) string {
	names := map[string]string{"shell.open": "open a terminal", "desktop.start": "start a remote desktop", "fs.list": "browse files", "fs.read": "download files"}
	var parts []string
	for _, op := range ops {
		if n, ok := names[op]; ok {
			parts = append(parts, n)
		} else {
			parts = append(parts, op)
		}
	}
	return strings.Join(parts, ", ")
}

func mustDecodeB64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return b
}

// grantAuth returns the grant that covers op on agentID for this operator.
// deny is set when the organization enforces signatures and none is held; the
// caller must refuse and tell the operator to open the feature again (the
// console asks for the grant before it connects).
func (s *Server) grantAuth(r *http.Request, agentID, op string) (auth *protocol.ActionAuth, deny string) {
	b := s.activeBundle(s.agentOrgID(agentID))
	if b == nil {
		return nil, ""
	}
	if u := userFrom(r.Context()); u != nil {
		if g := s.signing.grantFor(u.ID, agentID, op); g != nil {
			return g, ""
		}
	}
	if b.Mode() == actionauth.ModeEnforce {
		return nil, "signature required: open the session again to sign"
	}
	return nil, ""
}

// ---- small shared builders ----

func summaryDevices(n int, first string) string {
	if n <= 1 {
		return "on " + first
	}
	return fmt.Sprintf("on %d devices (including %s)", n, first)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
