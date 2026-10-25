package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/winwebauthn"
)

// promptTimeout bounds how long Windows waits for the operator's touch or
// Hello gesture.
const promptTimeout = 2 * time.Minute

var errNeedsWindows = errors.New("signing needs Windows: it uses Windows Hello or a security key through the Windows WebAuthn API. list and show work on this system")

func (a *app) cmdSign(ctx context.Context, args []string) error {
	fs, server := a.newFlags("sign")
	yes := fs.Bool("yes", false, "sign without asking for confirmation (the manifest is still printed)")
	all := fs.Bool("all", false, "sign every entry waiting for you, one at a time")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	switch {
	case *all && len(pos) > 0, !*all && len(pos) != 1:
		return usagef("usage: rmm-signer sign [--server URL] ID [--yes]   or   rmm-signer sign [--server URL] --all")
	}
	if a.needWindows {
		return errNeedsWindows
	}
	base, origin, err := a.target(*server)
	if err != nil {
		return err
	}
	cookie, err := a.authed(base)
	if err != nil {
		return err
	}
	if !*all {
		e, err := a.fetchEntry(ctx, base, cookie, pos[0])
		if err != nil {
			return err
		}
		_, err = a.signOne(ctx, base, origin, cookie, e, *yes)
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
	signed := 0
	for i := range list {
		fmt.Fprintf(a.out, "\n=== Entry %d of %d ===\n", i+1, len(list))
		done, err := a.signOne(ctx, base, origin, cookie, &list[i], *yes)
		if err != nil {
			// One failure ends the run: the rest may depend on it, and the
			// operator should read what went wrong before signing more.
			if signed > 0 {
				fmt.Fprintf(a.errw, "rmm-signer: stopped after %d signature(s).\n", signed)
			}
			return fmt.Errorf("entry %s: %w", safe(list[i].ManifestID), err)
		}
		if done {
			signed++
		}
	}
	fmt.Fprintf(a.out, "\nSigned %d of %d entries.\n", signed, len(list))
	return nil
}

// signOne prints one entry, asks, signs and posts. It reports whether a
// signature was posted; declining is not a failure.
func (a *app) signOne(ctx context.Context, base, origin, cookie string, e *entry, yes bool) (bool, error) {
	raw, m, err := e.decode()
	if err != nil {
		return false, err
	}
	if !originTrusted(origin, e.Origins) {
		return false, fmt.Errorf("this server's origin %s is not one the organization's trust bundle accepts (it accepts %s), so an assertion made for it would be rejected; use the console's own address as --server",
			origin, quoteList(e.Origins))
	}
	if e.RPID == "" {
		return false, errors.New("the server sent no relying party id for this entry, so it cannot be signed")
	}
	var allow [][]byte
	for _, c := range e.AllowCredentials {
		id, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(c, "="))
		if err != nil {
			return false, errors.New("a credential id the server sent is not base64url")
		}
		allow = append(allow, id)
	}
	if len(allow) == 0 {
		return false, errors.New("you have no registered security key in this organization's trust bundle; add one on the Security keys page first")
	}

	render(a.out, e, m)
	fmt.Fprintln(a.out)
	if !yes {
		fmt.Fprint(a.out, "Sign? [y/N] ")
		line, rerr := a.in.ReadString('\n')
		if ans := strings.ToLower(strings.TrimSpace(line)); ans != "y" && ans != "yes" {
			if rerr != nil && line == "" {
				fmt.Fprintln(a.out)
			}
			fmt.Fprintln(a.out, "Not signed.")
			return false, nil
		}
	}

	uv := e.UserVerification
	if uv != "required" && uv != "preferred" && uv != "discouraged" {
		uv = "preferred"
	}
	fmt.Fprintln(a.out, "Waiting for Windows Hello or your security key...")
	asrt, err := a.signer.GetAssertion(ctx, winwebauthn.Options{
		RPID:   e.RPID,
		Origin: origin,
		// The challenge is SHA-256 of the exact manifest bytes, as the
		// console makes it; the verifier recomputes it from the bytes it
		// holds, so the assertion binds those bytes and nothing else.
		Challenge:          actionauth.Challenge(raw),
		AllowCredentialIDs: allow,
		UserVerification:   uv,
		Timeout:            promptTimeout,
	})
	if err != nil {
		return false, signerError(err)
	}
	if asrt == nil || len(asrt.CredentialID) == 0 {
		return false, errors.New("the authenticator returned no assertion")
	}
	body := map[string]any{"assertion": protocol.Assertion{
		Cred: actionauth.EncodeB64(asrt.CredentialID),
		AD:   actionauth.EncodeB64(asrt.AuthenticatorData),
		CD:   actionauth.EncodeB64(asrt.ClientDataJSON),
		Sig:  actionauth.EncodeB64(asrt.Signature),
	}}
	// Posted with a fresh context so Ctrl-C after the touch does not
	// abandon a signature the authenticator already made.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	r, err := a.call(pctx, base, cookie, http.MethodPost, "/api/approvals/"+url.PathEscape(m.ID)+"/sign", body)
	if err != nil {
		return false, err
	}
	switch r.status {
	case http.StatusOK:
		fmt.Fprintf(a.out, "Signed. This was the last signature needed, so the action was released. %s\n", responseSummary(r.body))
		return true, nil
	case http.StatusAccepted:
		var p struct {
			Pending bool `json:"pending"`
			Have    int  `json:"have"`
			Need    int  `json:"need"`
		}
		_ = json.Unmarshal(r.body, &p)
		if p.Pending {
			fmt.Fprintf(a.out, "Signed. %d of %d signatures are in; the action runs when the rest arrive.\n", p.Have, p.Need)
			return true, nil
		}
		// Without the pending flag this is the released action's own answer.
		fmt.Fprintf(a.out, "Signed. This was the last signature needed, so the action was released. %s\n", responseSummary(r.body))
		return true, nil
	}
	if r.status >= 200 && r.status < 300 {
		fmt.Fprintf(a.out, "Signed. The server accepted the signature and released the action (HTTP %d). %s\n", r.status, responseSummary(r.body))
		return true, nil
	}
	switch r.status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict, http.StatusGone:
		// The server refused the signature itself.
		return false, apiError(r, base)
	}
	// Any other failure comes after the signature was taken: the last signature
	// releases the action, and the action's own failure (agent offline, timeout)
	// is what the sign request answers. Signing again would only meet 410.
	return false, fmt.Errorf("the signature was sent and probably recorded, but the action did not complete, and this request cannot be signed again; run rmm-signer list to see whether it is still waiting: %w", apiError(r, base))
}

func originTrusted(origin string, origins []string) bool {
	for _, o := range origins {
		if strings.EqualFold(strings.TrimRight(o, "/"), origin) {
			return true
		}
	}
	return false
}

func quoteList(l []string) string {
	if len(l) == 0 {
		return "no origins"
	}
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = safe(s)
	}
	return strings.Join(q, ", ")
}

func signerError(err error) error {
	switch {
	case errors.Is(err, winwebauthn.ErrUnsupported):
		return errNeedsWindows
	case errors.Is(err, winwebauthn.ErrCancelled):
		return errors.New("signing was cancelled at the Windows prompt; nothing was sent")
	case errors.Is(err, winwebauthn.ErrTimeout):
		return errors.New("the Windows prompt timed out before you confirmed; nothing was sent")
	case errors.Is(err, winwebauthn.ErrNoCredentials):
		return errors.New("none of your registered keys is available here; connect the security key you registered, or sign from the machine that has your Windows Hello credential")
	case errors.Is(err, context.Canceled):
		return errors.New("signing was interrupted; nothing was sent")
	}
	return fmt.Errorf("the authenticator did not sign: %w", err)
}

// responseSummary renders what the released action answered, as far as it is
// JSON the operator can read in a line or two.
func responseSummary(body []byte) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil || len(m) == 0 {
		return ""
	}
	for _, k := range []string{"summary", "message", "status"} {
		if s, ok := m[k].(string); ok && s != "" {
			return "The server answered: " + safe(s)
		}
	}
	out, _ := json.Marshal(m)
	s := string(out)
	if len(s) > 600 {
		s = s[:600] + "..."
	}
	return "The server answered: " + safe(s)
}
