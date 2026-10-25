package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Standing approvals (docs/plans/2026-10-06-phase3-signed-actions.md, 3.7).
//
// Work that runs with nobody present (scheduled tasks, automations, patch
// policies, catalog installs for the client portal, baselines) is authorized
// by a `standing` manifest an operator signed once. It names no device
// ("*": every agent of the organization) and binds the CONTENT instead: the
// hash of the script body, the power action, the baseline spec. The server
// attaches the stored approval to a run only while its content hash still
// matches what is about to be sent, and never blocks saving an object: an
// edited object simply stops matching until somebody signs it again.

const (
	approvalTask        = "task"
	approvalAutomation  = "automation"
	approvalPatchPolicy = "patch_policy"
	approvalCatalog     = "catalog_item"
	approvalBaseline    = "baseline"
)

var approvalTypes = []string{approvalTask, approvalAutomation, approvalPatchPolicy, approvalCatalog, approvalBaseline}

// standingRef names the object whose approval should authorize a run.
type standingRef struct {
	Type string
	ID   string
}

// approvalUnit is one thing an operator signs: an object (or one purpose of
// it: a policy installs and reboots, a catalog item installs per OS) with the
// constraints its approval must carry.
type approvalUnit struct {
	Type    string
	ID      string
	Purpose string
	Name    string
	Cons    actionauth.Constraints
	Hash    string // changes whenever what the approval covers changes
	AllOrgs bool   // true: runs wherever it is sent; otherwise Orgs
	Orgs    []string
	Err     string // set when the content cannot be bound (e.g. a float in a spec)
}

func (u approvalUnit) appliesTo(org string) bool {
	return u.AllOrgs || slices.Contains(u.Orgs, org)
}

// unitHash binds the constraints and any object content the constraints do
// not carry (a patch policy's mode).
func unitHash(c actionauth.Constraints, extra string) string {
	raw, _ := json.Marshal(c)
	canon, err := actionauth.CanonicalizeJSON(raw)
	if err != nil {
		canon = raw
	}
	sum := sha256.Sum256(append(append(canon, 0), extra...))
	return hex.EncodeToString(sum[:])
}

func scriptConstraints(lang, body string, args []string) actionauth.Constraints {
	sum := sha256.Sum256([]byte(body))
	if len(args) == 0 {
		args = nil
	}
	return actionauth.Constraints{Op: protocol.ReqScriptRun, BodySHA256: hex.EncodeToString(sum[:]), Language: lang, Args: args}
}

func scriptUnit(typ, id, purpose, name, lang, body string, args []string) approvalUnit {
	c := scriptConstraints(lang, body, args)
	return approvalUnit{Type: typ, ID: id, Purpose: purpose, Name: name, Cons: c, Hash: unitHash(c, "")}
}

func rebootUnit(typ, id, purpose, name string) approvalUnit {
	c := actionauth.Constraints{Op: protocol.ReqPower, PowerAction: "reboot"}
	return approvalUnit{Type: typ, ID: id, Purpose: purpose, Name: name, Cons: c, Hash: unitHash(c, "")}
}

func installUnit(typ, id, purpose, name, extra string) approvalUnit {
	c := actionauth.Constraints{Op: protocol.ReqUpdatesInstall}
	return approvalUnit{Type: typ, ID: id, Purpose: purpose, Name: name, Cons: c, Hash: unitHash(c, extra)}
}

// baselineUnit binds a baseline spec exactly as it is placed into agent.config.
func baselineUnit(spec protocol.BaselineSpec) approvalUnit {
	u := approvalUnit{Type: approvalBaseline, ID: strconv.FormatInt(spec.ID, 10), Name: spec.Name}
	raw, err := json.Marshal(spec)
	if err == nil {
		var h string
		if h, err = actionauth.SpecHash(raw); err == nil {
			u.Cons = actionauth.Constraints{Op: actionauth.SpecOp, SpecSHA256: h}
			u.Hash = unitHash(u.Cons, "")
			return u
		}
	}
	u.Err = "the baseline cannot be signed: " + err.Error()
	return u
}

func taskUnit(t *Task, sc *Script) (approvalUnit, bool) {
	id := strconv.FormatInt(t.ID, 10)
	switch t.Kind {
	case "script":
		if sc == nil {
			return approvalUnit{}, false
		}
		return scriptUnit(approvalTask, id, "", t.Name, sc.Language, sc.Body, t.Args), true
	case "reboot":
		return rebootUnit(approvalTask, id, "", t.Name), true
	case "patch_install":
		var o struct {
			Reboot bool `json:"reboot_if_required"`
		}
		json.Unmarshal(t.Options, &o)
		return installUnit(approvalTask, id, "", t.Name, fmt.Sprintf("reboot_if_required=%v", o.Reboot)), true
	}
	return approvalUnit{}, false
}

func (s *Server) unitForTask(t *Task) (approvalUnit, bool) {
	var sc *Script
	if t.Kind == "script" && t.ScriptID != nil {
		sc, _ = s.db.GetScript(*t.ScriptID)
	}
	return taskUnit(t, sc)
}

// policyUnits are the approvals a patch policy needs: its installs, and the
// reboot afterwards when it reboots always.
func policyUnits(p *PatchPolicy) (install approvalUnit, reboot *approvalUnit) {
	id := strconv.FormatInt(p.ID, 10)
	install = installUnit(approvalPatchPolicy, id, "install", p.Name, "mode="+p.Mode)
	if p.Reboot == "always" {
		ru := rebootUnit(approvalPatchPolicy, id, "reboot", p.Name+" (reboot after patching)")
		reboot = &ru
	}
	return install, reboot
}

// ---- storage ----

type approvalRow struct {
	Org       string
	Type      string
	ID        string
	Purpose   string
	Hash      string
	Manifest  []byte
	Sigs      []protocol.Assertion
	Need      int
	CreatedBy string
	CreatedAt int64
	ExpiresAt int64
	// LogIndex is the manifest's leaf in the transparency log, -1 when it was
	// stored before the log existed or no log is attached. putApproval sets it;
	// a value passed in is ignored.
	LogIndex int64
}

func (d *DB) approvalsFor(org, typ, id string) []approvalRow {
	rows, err := d.Query(`SELECT org_id, object_type, object_id, purpose, content_hash, manifest, sigs, need, created_by, created_at, expires_at, log_index
		FROM approvals WHERE org_id = ? AND object_type = ? AND object_id = ? ORDER BY purpose`, org, typ, id)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []approvalRow
	for rows.Next() {
		var a approvalRow
		var sigs string
		if rows.Scan(&a.Org, &a.Type, &a.ID, &a.Purpose, &a.Hash, &a.Manifest, &sigs, &a.Need, &a.CreatedBy, &a.CreatedAt, &a.ExpiresAt, &a.LogIndex) != nil {
			continue
		}
		json.Unmarshal([]byte(sigs), &a.Sigs)
		out = append(out, a)
	}
	return out
}

// putApproval stores a standing approval and logs its manifest once, here,
// so every dispatch of it can prove the leaf. Without a log attached the row
// keeps log_index -1. A log that fails refuses the approval: storing it
// would hand devices a manifest the log never saw.
func (d *DB) putApproval(a approvalRow) error {
	a.LogIndex = -1
	if d.logAppend != nil {
		leaf, err := actionauth.ManifestLeaf(&protocol.ActionAuth{M: actionauth.EncodeB64(a.Manifest), S: a.Sigs})
		if err == nil {
			a.LogIndex, err = d.logAppend("manifest", leaf)
		}
		if err != nil {
			return fmt.Errorf("the transparency log could not record this approval, so it was not stored: %w", err)
		}
	}
	_, err := d.Exec(`INSERT INTO approvals(org_id, object_type, object_id, purpose, content_hash, manifest, sigs, need, created_by, created_at, expires_at, log_index)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(org_id, object_type, object_id, purpose) DO UPDATE SET content_hash=excluded.content_hash, manifest=excluded.manifest,
			sigs=excluded.sigs, need=excluded.need, created_by=excluded.created_by, created_at=excluded.created_at, expires_at=excluded.expires_at,
			log_index=excluded.log_index`,
		a.Org, a.Type, a.ID, a.Purpose, a.Hash, a.Manifest, jsonText(nonNil(a.Sigs)), a.Need, a.CreatedBy, a.CreatedAt, a.ExpiresAt, a.LogIndex)
	return err
}

// backfillApprovalLog logs the manifest of an approval stored before the
// transparency log existed (log_index -1) the first time it is dispatched, and
// remembers the leaf. Without this, turning on require_log_proof would stop
// every scheduled task and automation until each one was signed again. It
// returns -1 when no log is attached or the log could not take the leaf, in
// which case the approval dispatches without a proof as before.
func (d *DB) backfillApprovalLog(row approvalRow, a *protocol.ActionAuth) int64 {
	if d.logAppend == nil {
		return -1
	}
	leaf, err := actionauth.ManifestLeaf(a)
	if err != nil {
		return -1
	}
	idx, err := d.logAppend("manifest", leaf)
	if err != nil {
		slog.Warn("cannot log a standing approval that predates the transparency log", "type", row.Type, "id", row.ID, "err", err)
		return -1
	}
	if _, err := d.Exec(`UPDATE approvals SET log_index = ? WHERE org_id = ? AND object_type = ? AND object_id = ? AND purpose = ? AND log_index < 0`,
		idx, row.Org, row.Type, row.ID, row.Purpose); err != nil {
		slog.Warn("cannot remember the log leaf of a standing approval", "type", row.Type, "id", row.ID, "err", err)
	}
	return idx
}

func (d *DB) bundleOrgIDs() []string {
	rows, err := d.Query(`SELECT DISTINCT org_id FROM trust_bundles ORDER BY org_id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var o string
		if rows.Scan(&o) == nil {
			out = append(out, o)
		}
	}
	return out
}

// ---- validity and attachment ----

func (r approvalRow) usable(b *actionauth.Bundle) (reason string) {
	if r.ExpiresAt <= now() {
		return "expired"
	}
	owners, _ := actionauth.Signers(r.Manifest, r.Sigs, b)
	if len(owners) < max(1, b.Policy.HighThreshold) {
		return "missing" // the bundle moved on: these signatures no longer count
	}
	return ""
}

// approvalAuth is the stored approval that still covers unit in org, or nil.
func (s *Server) approvalAuth(org string, u approvalUnit) *protocol.ActionAuth {
	b := s.activeBundle(org)
	if b == nil || u.Err != "" || u.Hash == "" {
		return nil
	}
	for _, row := range s.db.approvalsFor(org, u.Type, u.ID) {
		if row.Hash == u.Hash && row.usable(b) == "" {
			a := &protocol.ActionAuth{M: actionauth.EncodeB64(row.Manifest), S: row.Sigs}
			if row.LogIndex < 0 {
				row.LogIndex = s.db.backfillApprovalLog(row, a)
			}
			if row.LogIndex >= 0 {
				a.L = &protocol.LogProof{Index: row.LogIndex}
			}
			return a
		}
	}
	return nil
}

// approvalState says why unit has no valid approval in org ("" when it has).
func (s *Server) approvalState(org string, u approvalUnit, b *actionauth.Bundle) string {
	var found *approvalRow
	for _, row := range s.db.approvalsFor(org, u.Type, u.ID) {
		if row.Purpose == u.Purpose {
			row := row
			found = &row
		}
	}
	switch {
	case found == nil || u.Err != "":
		return "missing"
	case found.Hash != u.Hash:
		return "content changed"
	}
	return found.usable(b)
}

// standingAuthForScript is the approval for an unattended script run of ref
// on agentID, checked against the exact body about to be sent.
func (s *Server) standingAuthForScript(agentID string, ref standingRef, lang, body string, args []string) *protocol.ActionAuth {
	org := s.agentOrgID(agentID)
	if s.activeBundle(org) == nil {
		return nil
	}
	return s.approvalAuth(org, scriptUnit(ref.Type, ref.ID, "", "", lang, body, args))
}

// standingAuthForUnit attaches the approval for a non-script unit to agentID.
func (s *Server) standingAuthForUnit(agentID string, u approvalUnit, ok bool) *protocol.ActionAuth {
	if !ok {
		return nil
	}
	return s.approvalAuth(s.agentOrgID(agentID), u)
}

// baselineAuthFor maps each spec's decimal ID to its approval.
func (s *Server) baselineAuthFor(org string, specs []protocol.BaselineSpec) map[string]*protocol.ActionAuth {
	if s.activeBundle(org) == nil {
		return nil
	}
	var out map[string]*protocol.ActionAuth
	for _, sp := range specs {
		if auth := s.approvalAuth(org, baselineUnit(sp)); auth != nil {
			if out == nil {
				out = map[string]*protocol.ActionAuth{}
			}
			out[strconv.FormatInt(sp.ID, 10)] = auth
		}
	}
	return out
}

// ---- enumerating what needs approving ----

func orgsMatching(agents []*Agent, t Targets) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range agents {
		if t.Matches(a) && !seen[a.OrgID] {
			seen[a.OrgID] = true
			out = append(out, a.OrgID)
		}
	}
	return out
}

// objectUnits lists the approvals every unattended object needs. typ and id
// narrow it ("" matches all).
func (s *Server) objectUnits(typ, id string) []approvalUnit {
	var out []approvalUnit
	want := func(t, i string) bool { return (typ == "" || typ == t) && (id == "" || id == i) }
	var agents []*Agent
	loadAgents := func() []*Agent {
		if agents == nil {
			agents, _ = s.db.ListAgents()
		}
		return agents
	}
	add := func(u approvalUnit, orgs []string) {
		u.Orgs = orgs
		out = append(out, u)
	}

	if typ == "" || typ == approvalTask {
		tasks, _ := s.db.ListTasks()
		for i := range tasks {
			t := &tasks[i]
			if !t.Enabled || !want(approvalTask, strconv.FormatInt(t.ID, 10)) {
				continue
			}
			if u, ok := s.unitForTask(t); ok {
				add(u, orgsMatching(loadAgents(), t.Targets))
			}
		}
	}
	if typ == "" || typ == approvalAutomation {
		autos, _ := s.db.ListAutomations()
		for _, a := range autos {
			if !a.Enabled || a.Action != "run_script" || !want(approvalAutomation, strconv.FormatInt(a.ID, 10)) {
				continue
			}
			var p struct {
				ScriptID int64    `json:"script_id"`
				Args     []string `json:"args"`
			}
			var f struct {
				Targets *Targets `json:"targets"`
			}
			json.Unmarshal(a.ActionParams, &p)
			json.Unmarshal(a.Filter, &f)
			sc, err := s.db.GetScript(p.ScriptID)
			if err != nil {
				continue
			}
			u := scriptUnit(approvalAutomation, strconv.FormatInt(a.ID, 10), "", a.Name, sc.Language, sc.Body, p.Args)
			if f.Targets == nil {
				u.AllOrgs = true
				out = append(out, u)
			} else {
				add(u, orgsMatching(loadAgents(), *f.Targets))
			}
		}
	}
	if typ == "" || typ == approvalPatchPolicy {
		pols, _ := s.db.ListPatchPolicies()
		for i := range pols {
			p := &pols[i]
			if !p.Enabled || p.InstallSchedule == "" || !want(approvalPatchPolicy, strconv.FormatInt(p.ID, 10)) {
				continue
			}
			orgs := orgsMatching(loadAgents(), p.Targets)
			inst, reb := policyUnits(p)
			add(inst, orgs)
			if reb != nil {
				add(*reb, orgs)
			}
		}
	}
	if typ == "" || typ == approvalCatalog {
		items, _ := s.db.ListSoftwareCatalog("")
		for i := range items {
			it := &items[i]
			if !want(approvalCatalog, it.ID) {
				continue
			}
			seen := map[string]bool{}
			for _, fam := range []string{"windows", "linux"} {
				if it.OS != "" && it.OS != "all" && it.OS != fam {
					continue
				}
				lang := "bash"
				if fam == "windows" {
					lang = "powershell"
				}
				for _, action := range []string{"install", "uninstall", "update"} {
					body := catalogBody(it, action, fam == "windows")
					if strings.TrimSpace(body) == "" {
						continue
					}
					u := scriptUnit(approvalCatalog, it.ID, action+":"+fam, fmt.Sprintf("%s (%s, %s)", it.Name, action, fam), lang, body, nil)
					if seen[u.Hash] {
						continue // the same text is already covered by another purpose
					}
					seen[u.Hash] = true
					u.AllOrgs = true
					out = append(out, u)
				}
			}
		}
	}
	if typ == "" || typ == approvalBaseline {
		list, _ := s.db.ListBaselinesWithChecks()
		for _, b := range list {
			if !b.Enabled || !want(approvalBaseline, strconv.FormatInt(b.ID, 10)) {
				continue
			}
			add(baselineUnit(baselineSpec(b)), orgsMatching(loadAgents(), b.Targets))
		}
	}
	return out
}

// signingOrgs are the organizations (the caller may reach) whose bundle is on.
func (s *Server) signingOrgs(u *User, only string) []string {
	var out []string
	for _, org := range s.db.bundleOrgIDs() {
		if (only == "" || only == org) && s.canAccessAgent(u, org) && s.activeBundle(org) != nil {
			out = append(out, org)
		}
	}
	return out
}

func (s *Server) handleUnsignedApprovals(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	out := []map[string]any{}
	orgs := s.signingOrgs(u, r.URL.Query().Get("org"))
	if len(orgs) > 0 {
		units := s.objectUnits("", "")
		for _, org := range orgs {
			b := s.activeBundle(org)
			for _, un := range units {
				if !un.appliesTo(org) {
					continue
				}
				if reason := s.approvalState(org, un, b); reason != "" {
					out = append(out, map[string]any{"type": un.Type, "id": un.ID, "name": un.Name, "reason": reason, "org": org, "purpose": un.Purpose})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i]["type"] != out[j]["type"] {
			return out[i]["type"].(string) < out[j]["type"].(string)
		}
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSignObject(w http.ResponseWriter, r *http.Request) {
	typ, id := r.PathValue("type"), r.PathValue("id")
	if !slices.Contains(approvalTypes, typ) {
		writeErr(w, http.StatusBadRequest, "unknown object type "+strconv.Quote(typ))
		return
	}
	q := r.URL.Query()
	wantOrg, wantPurpose := q.Get("org"), q.Get("purpose")
	me := userFrom(r.Context())
	units := s.objectUnits(typ, id)
	type cand struct {
		org     string
		unit    approvalUnit
		state   string
		matched bool // passes the org and purpose the caller asked for
	}
	var cands []cand
	anyMatch := false
	for _, org := range s.signingOrgs(me, wantOrg) {
		b := s.activeBundle(org)
		for _, un := range units {
			if un.appliesTo(org) {
				m := wantPurpose == "" || un.Purpose == wantPurpose
				anyMatch = anyMatch || m
				cands = append(cands, cand{org, un, s.approvalState(org, un, b), m})
			}
		}
	}
	if !anyMatch {
		writeErr(w, http.StatusNotFound, "nothing to approve: the object does not exist, is disabled, or runs in no organization that signs actions")
		return
	}
	// remaining counts every other unit of the object that still needs a
	// signature, whatever purpose was asked for, so a caller that signs one unit
	// at a time knows whether to come back.
	unsigned := 0
	for _, c := range cands {
		if c.state != "" {
			unsigned++
		}
	}
	// With both org and purpose the caller names one unit: signing an approved
	// one again would only spend a key touch, so say it is done.
	exact := wantOrg != "" && wantPurpose != ""
	pick := -1
	for i, c := range cands {
		if c.matched && (c.state != "" || exact) {
			pick = i
			break
		}
	}
	if pick >= 0 && exact && cands[pick].state == "" {
		writeJSON(w, http.StatusOK, map[string]any{"expires_at": s.soonestApproval(cands[pick].org, typ, id, cands[pick].unit.Purpose), "already_approved": true, "remaining": unsigned})
		return
	}
	if pick < 0 {
		var soonest int64
		for _, c := range cands {
			if !c.matched {
				continue
			}
			if e := s.soonestApproval(c.org, typ, id, c.unit.Purpose); e != 0 && (soonest == 0 || e < soonest) {
				soonest = e
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"expires_at": soonest, "already_approved": true, "remaining": unsigned})
		return
	}
	remaining := unsigned - 1 // the unit being signed now is not "still" unsigned
	c := cands[pick]
	if c.unit.Err != "" {
		writeErr(w, http.StatusBadRequest, c.unit.Err)
		return
	}
	cons := c.unit.Cons
	hash, org, unit := c.unit.Hash, c.org, c.unit
	s.runSigned(w, r, signedAction{
		Kind: actionauth.KindStanding, Org: org, Targets: []string{"*"}, Constraints: &cons, TTL: standingTTL,
		Summary: standingSummary(unit, org),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			if auth == nil {
				writeErr(w, http.StatusConflict, "an approval needs a signature")
				return
			}
			raw := mustDecodeB64(auth.M)
			m, err := actionauth.ParseManifest(raw)
			if err != nil {
				fail(w, err)
				return
			}
			need := 1
			if b := s.activeBundle(org); b != nil {
				need = max(1, b.Policy.HighThreshold)
			}
			if err := s.db.putApproval(approvalRow{Org: org, Type: unit.Type, ID: unit.ID, Purpose: unit.Purpose, Hash: hash,
				Manifest: raw, Sigs: auth.S, Need: need, CreatedBy: actor(r), CreatedAt: now(), ExpiresAt: m.Exp}); err != nil {
				fail(w, err)
				return
			}
			s.audit(r, "approval.sign", unit.Type+"/"+unit.ID, map[string]any{"org": org, "purpose": unit.Purpose, "name": unit.Name, "expires_at": m.Exp, "hash": hash})
			if unit.Type == approvalBaseline {
				s.pushOrgConfig(org)
			}
			writeJSON(w, http.StatusOK, map[string]any{"expires_at": m.Exp, "org": org, "purpose": unit.Purpose, "remaining": remaining})
		},
	})
}

// soonestApproval is when the earliest-expiring approval of one purpose of an
// object ends in org, or 0 when there is none.
func (s *Server) soonestApproval(org, typ, id, purpose string) int64 {
	var soonest int64
	for _, row := range s.db.approvalsFor(org, typ, id) {
		if row.Purpose == purpose && (soonest == 0 || row.ExpiresAt < soonest) {
			soonest = row.ExpiresAt
		}
	}
	return soonest
}

func standingSummary(u approvalUnit, org string) string {
	what := map[string]string{
		approvalTask: "scheduled task", approvalAutomation: "alert automation", approvalPatchPolicy: "patch policy",
		approvalCatalog: "software catalog item", approvalBaseline: "baseline",
	}[u.Type]
	var detail string
	switch u.Cons.Op {
	case protocol.ReqScriptRun:
		detail = fmt.Sprintf("run only this %s script (SHA-256 %s)", u.Cons.Language, clip(u.Cons.BodySHA256, 16))
	case protocol.ReqPower:
		detail = "reboot only"
	case protocol.ReqUpdatesInstall:
		detail = "install OS updates"
	case actionauth.SpecOp:
		detail = fmt.Sprintf("hold exactly this baseline definition (SHA-256 %s)", clip(u.Cons.SpecSHA256, 16))
	}
	return fmt.Sprintf("Approve the %s %q to run unattended on every device of %s for 180 days: %s", what, u.Name, org, detail)
}

// pushOrgConfig sends the current agent config to every online device of org.
func (s *Server) pushOrgConfig(org string) {
	rows, err := s.db.Query(`SELECT id FROM agents WHERE org_id = ?`, org)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if s.hub.IsOnline(id) {
			s.pushAgentConfig(id)
		}
	}
}
