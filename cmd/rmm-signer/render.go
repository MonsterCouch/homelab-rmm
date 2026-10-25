package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// entry is one pending approval as GET /api/approvals answers it. Only
// Manifest is trusted for what gets signed; everything else is routing
// (which key, which origin) or the server's own words.
type entry struct {
	ManifestID       string            `json:"manifest_id"`
	Manifest         string            `json:"manifest"`
	Summary          string            `json:"summary"`
	Have             int               `json:"have"`
	Need             int               `json:"need"`
	Issuer           string            `json:"issuer"`
	Org              string            `json:"org"`
	CreatedAt        int64             `json:"created_at"`
	ExpiresAt        int64             `json:"expires_at"`
	TargetNames      map[string]string `json:"target_names"`
	RPID             string            `json:"rp_id"`
	Origins          []string          `json:"origins"`
	AllowCredentials []string          `json:"allow_credentials"`
	UserVerification string            `json:"user_verification"`
	Signers          []string          `json:"signers"`
}

func (a *app) fetchEntries(ctx context.Context, base, cookie string) ([]entry, error) {
	r, err := a.call(ctx, base, cookie, http.MethodGet, "/api/approvals", nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, apiError(r, base)
	}
	var list []entry
	if err := json.Unmarshal(r.body, &list); err != nil {
		return nil, errors.New("the server's list of approvals is not in the expected form; is --server the console's address?")
	}
	return list, nil
}

func (a *app) fetchEntry(ctx context.Context, base, cookie, id string) (*entry, error) {
	r, err := a.call(ctx, base, cookie, http.MethodGet, "/api/approvals/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	if r.status != http.StatusOK {
		return nil, apiError(r, base)
	}
	var e entry
	if err := json.Unmarshal(r.body, &e); err != nil {
		return nil, errors.New("the server's answer is not in the expected form; is --server the console's address?")
	}
	return &e, nil
}

// decode returns the exact manifest bytes of e and their parse. It refuses an
// entry whose manifest is not the one its id names, so a listing cannot
// present one document under another's id.
func (e *entry) decode() ([]byte, *actionauth.Manifest, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(e.Manifest, "="))
	if err != nil {
		return nil, nil, errors.New("the manifest the server sent is not base64url")
	}
	m, err := actionauth.ParseManifest(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("the manifest the server sent is not valid, so it will not be shown or signed: %w", err)
	}
	if m.ID != e.ManifestID {
		return nil, nil, fmt.Errorf("the server listed manifest %s, but its bytes carry the id %s; refusing it", one(e.ManifestID), one(m.ID))
	}
	return raw, m, nil
}

func (a *app) cmdList(ctx context.Context, args []string) error {
	fs, server := a.newFlags("list")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("list takes no arguments.")
	}
	base, _, err := a.target(*server)
	if err != nil {
		return err
	}
	cookie, err := a.authed(base)
	if err != nil {
		return err
	}
	list, err := a.fetchEntries(ctx, base, cookie)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(a.out, "Nothing is waiting for your signature.")
		return nil
	}
	for _, e := range list {
		// What a row says comes from the manifest bytes; the server's
		// summary is shown only as such.
		_, m, derr := e.decode()
		if derr != nil {
			fmt.Fprintf(a.out, "%s  UNREADABLE: %v\n", one(e.ManifestID), derr)
			continue
		}
		what := m.Kind
		switch m.Kind {
		case actionauth.KindAction:
			what = m.Op
		case actionauth.KindGrant:
			what = "grant " + strings.Join(m.Ops, ",")
		case actionauth.KindStanding:
			what = "standing " + m.Constraints.Op
		}
		fmt.Fprintf(a.out, "%s  %s  org %s  %d of %d signed  expires %s  by %s  (%d target(s))\n",
			one(m.ID), one(what), one(m.Org), e.Have, e.Need, stamp(m.Exp), one(m.Issuer), len(m.Targets))
	}
	return nil
}

func (a *app) cmdShow(ctx context.Context, args []string) error {
	fs, server := a.newFlags("show")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: rmm-signer show [--server URL] ID")
	}
	base, _, err := a.target(*server)
	if err != nil {
		return err
	}
	cookie, err := a.authed(base)
	if err != nil {
		return err
	}
	e, err := a.fetchEntry(ctx, base, cookie, pos[0])
	if err != nil {
		return err
	}
	_, m, err := e.decode()
	if err != nil {
		return err
	}
	render(a.out, e, m)
	return nil
}

func stamp(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// safe makes text from the manifest or the server printable without letting it
// move the cursor or restyle the screen: a script body is attacker-shaped
// input, and an escape sequence could hide the line the operator must read.
// Newlines and tabs stay; every other control character is shown as \xNN or
// \uNNNN. Format characters (zero-width, direction marks, tag characters) and
// line or paragraph separators are escaped by category, not from a hand-kept
// list, because each of them can hide or reorder what the operator reads.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r >= 0x80 && r < 0xa0, r == 0xfffd, unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			if r > 0xffff {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// one is safe for a value printed on one line next to a label. A newline in a
// manifest field must not be able to start a line that looks like another
// field, so it is shown as \n; literal newlines stay only in blocks where
// every line is indented.
func one(s string) string {
	return strings.ReplaceAll(safe(s), "\n", `\n`)
}

// indent prefixes every line of s.
func indent(s, pad string) string {
	s = safe(strings.TrimRight(s, "\n"))
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

// render prints everything the manifest says, then the server's own
// additions marked as such. Nothing here comes from the entry except the
// device names and the summary.
func render(w io.Writer, e *entry, m *actionauth.Manifest) {
	fmt.Fprintf(w, "Manifest      %s\n", one(m.ID))
	fmt.Fprintf(w, "Kind          %s\n", one(m.Kind))
	fmt.Fprintf(w, "Organization  %s\n", one(m.Org))
	fmt.Fprintf(w, "Issuer        %s\n", one(m.Issuer))
	fmt.Fprintf(w, "Issued        %s\n", stamp(m.IAT))
	fmt.Fprintf(w, "Expires       %s\n", stamp(m.Exp))
	fmt.Fprintf(w, "Signed        %d of %d", e.Have, e.Need)
	if len(e.Signers) > 0 {
		fmt.Fprintf(w, " (by %s; names from the server)", one(strings.Join(e.Signers, ", ")))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Targets       %d\n", len(m.Targets))
	for _, t := range m.Targets {
		switch name := e.TargetNames[t]; {
		case t == "*":
			fmt.Fprintln(w, "  * (every device in the organization)")
		case name != "":
			fmt.Fprintf(w, "  %s  %q (name from the server)\n", one(t), one(name))
		default:
			fmt.Fprintf(w, "  %s\n", one(t))
		}
	}
	switch m.Kind {
	case actionauth.KindAction:
		fmt.Fprintf(w, "Operation     %s\n", one(m.Op))
		renderPayload(w, m)
	case actionauth.KindGrant:
		fmt.Fprintf(w, "Grants        %s\n", one(strings.Join(m.Ops, ", ")))
	case actionauth.KindStanding:
		c := m.Constraints
		fmt.Fprintln(w, "Standing approval: the agent may run, without asking again, anything that matches")
		fmt.Fprintf(w, "  Operation     %s\n", one(c.Op))
		for _, kv := range [][2]string{
			{"Language", c.Language}, {"Body SHA-256", c.BodySHA256}, {"Power action", c.PowerAction}, {"Spec SHA-256", c.SpecSHA256},
		} {
			if kv[1] != "" {
				fmt.Fprintf(w, "  %-13s %s\n", kv[0], one(kv[1]))
			}
		}
		if c.Args != nil {
			fmt.Fprintf(w, "  Args          %s\n", jsonLine(c.Args))
		}
	}
	fmt.Fprintf(w, "Nonce         %s\n", one(m.Nonce))
	if e.Summary != "" {
		fmt.Fprintf(w, "\nServer's summary (the server's words, not part of what is signed):\n%s\n", indent(e.Summary, "  "))
	}
}

func jsonLine(v any) string {
	b, _ := json.Marshal(v)
	return safe(string(b))
}

func renderPayload(w io.Writer, m *actionauth.Manifest) {
	if len(m.Payload) == 0 {
		fmt.Fprintln(w, "Payload       (none)")
		return
	}
	switch m.Op {
	case protocol.ReqScriptRun:
		var p protocol.ScriptRun
		if strictDecode(m.Payload, &p) == nil {
			fmt.Fprintf(w, "Language      %s\n", one(p.Language))
			fmt.Fprintf(w, "Timeout       %d seconds\n", p.Timeout)
			if p.RunAs != "" {
				fmt.Fprintf(w, "Run as        %s\n", one(p.RunAs))
			}
			if p.MaxMemoryMB != 0 {
				fmt.Fprintf(w, "Memory limit  %d MB\n", p.MaxMemoryMB)
			}
			if p.CPULimitPercent != 0 {
				fmt.Fprintf(w, "CPU limit     %d%%\n", p.CPULimitPercent)
			}
			if p.RunID != "" {
				fmt.Fprintf(w, "Run id        %s\n", one(p.RunID))
			}
			if len(p.Args) > 0 {
				fmt.Fprintf(w, "Arguments     %s\n", jsonLine(p.Args))
			}
			if len(p.Env) == 0 {
				fmt.Fprintln(w, "Environment   (none)")
			} else {
				fmt.Fprintln(w, "Environment")
				keys := make([]string, 0, len(p.Env))
				for k := range p.Env {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fmt.Fprintf(w, "  %s=%s\n", one(k), one(p.Env[k]))
				}
			}
			fmt.Fprintf(w, "Script body (%d bytes, shown in full)\n%s\n", len(p.Body), indent(p.Body, "  | "))
			return
		}
	case protocol.ReqAgentUpdate:
		var p protocol.AgentUpdate
		if strictDecode(m.Payload, &p) == nil {
			fmt.Fprintf(w, "Update URL    %s\n", one(p.URL))
			fmt.Fprintf(w, "SHA-256       %s\n", one(p.SHA256))
			fmt.Fprintf(w, "Version       %s\n", one(p.Version))
			return
		}
	}
	// Anything else, and a payload with fields this tool does not know, is
	// printed as it is rather than summarized.
	var pretty bytes.Buffer
	if json.Indent(&pretty, m.Payload, "", "  ") != nil {
		pretty.Reset()
		pretty.Write(m.Payload)
	}
	fmt.Fprintf(w, "Payload\n%s\n", indent(pretty.String(), "  "))
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
