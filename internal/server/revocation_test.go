package server

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/actionauth/authtest"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// These tests cover what revoking an operator's access has to reach: the
// streams they already have open, their second factor, the login limiter,
// and their standing as a signer.

func userID(t *testing.T, s *Server, username string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id); err != nil {
		t.Fatalf("no user %q: %v", username, err)
	}
	return id
}

func openStreams(s *Server) int {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	return len(s.live.m)
}

// A terminal is authorized when it opens. Everything that takes the
// operator's access away afterwards must end it, and must tell the device to
// close the shell, rather than leave a SYSTEM prompt attached to a session
// that no longer exists.
func TestOpenTerminalEndsWhenAccessIsRevoked(t *testing.T) {
	revocations := map[string]func(t *testing.T, s *Server, admin, tech *browser, id int64){
		"sign out": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			tech.mustJSON("POST", "/api/auth/logout", nil, nil)
		},
		"password reset by an administrator": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", id), map[string]any{"password": "newpassword1"}, nil)
		},
		"demotion to viewer": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", id), map[string]any{"role": "viewer"}, nil)
		},
		"scope narrowed to another organization": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			var org struct {
				ID string `json:"id"`
			}
			admin.mustJSON("POST", "/api/organizations", map[string]string{"name": "Elsewhere"}, &org)
			if org.ID == "" {
				t.Fatal("no organization id")
			}
			admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", id), map[string]any{"org_scope": []string{org.ID}}, nil)
		},
		"account deleted": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			admin.mustJSON("DELETE", fmt.Sprintf("/api/users/%d", id), nil, nil)
		},
		// Nothing tells the server about these; the periodic sweep finds them.
		"session row removed behind the server's back": func(t *testing.T, s *Server, admin, tech *browser, id int64) {
			if _, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
				t.Fatal(err)
			}
			s.recheckStreams() // what watchStreams does every liveRecheckEvery
		},
	}
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			s, ts, admin := newTestServerWith(t, Config{})
			var tok struct{ Token string }
			admin.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
			agent := newShellAgent(t, ts, tok.Token, "revbox", "")
			waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

			admin.mustJSON("POST", "/api/users", map[string]string{"username": "t1", "password": "password123", "role": "tech"}, nil)
			tech := newBrowser(t, ts)
			tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "t1", "password": "password123"}, nil)
			id := userID(t, s, "t1")

			// The administrator's own terminal is the control: revoking t1
			// must not touch it.
			mine, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, admin))
			if err != nil {
				t.Fatalf("admin terminal dial: %v", err)
			}
			defer mine.Close()
			mine.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
			if m := readShell(t, mine); m["t"] != "opened" {
				t.Fatalf("admin terminal: expected opened, got %v", m)
			}

			term, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, tech))
			if err != nil {
				t.Fatalf("terminal dial: %v", err)
			}
			defer term.Close()
			term.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
			opened := readShell(t, term)
			if opened["t"] != "opened" {
				t.Fatalf("expected opened, got %v", opened)
			}
			session, _ := opened["session"].(string)
			if p := readShell(t, term); p["t"] != "out" {
				t.Fatalf("expected the prompt, got %v", p)
			}
			if n := openStreams(s); n != 2 {
				t.Fatalf("%d streams tracked, want 2", n)
			}

			revoke(t, s, admin, tech, id)

			// The server closes the socket with a policy close, not a
			// network drop, so the viewer can say why.
			term.SetReadDeadline(time.Now().Add(5 * time.Second))
			var closeErr *websocket.CloseError
			for {
				_, _, err := term.ReadMessage()
				if err == nil {
					continue
				}
				if !errors.As(err, &closeErr) {
					t.Fatalf("terminal ended with %v, want a close frame", err)
				}
				break
			}
			if closeErr.Code != websocket.ClosePolicyViolation {
				t.Errorf("close code = %d, want %d", closeErr.Code, websocket.ClosePolicyViolation)
			}
			// ... and the shell on the device goes with it.
			deadline := time.After(5 * time.Second)
			for closed := false; !closed; {
				select {
				case got := <-agent.closes:
					closed = got == session
				case <-deadline:
					t.Fatal("the device was never told to close the revoked operator's shell")
				}
			}
			waitFor(t, "the revoked stream to be forgotten", func() bool { return openStreams(s) == 1 })

			// The administrator's terminal is still attached.
			if err := mine.WriteJSON(map[string]any{"t": "resize", "cols": 100, "rows": 30}); err != nil {
				t.Fatalf("admin terminal write after the revocation: %v", err)
			}
			s.recheckStreams()
			if n := openStreams(s); n != 1 {
				t.Fatalf("%d streams tracked after a second pass, want the administrator's 1", n)
			}
		})
	}
}

// Changing your own password ends your other sessions, and what they had
// open, but not the session that made the change.
func TestPasswordChangeEndsOtherSessionsStreams(t *testing.T) {
	s, ts, admin := newTestServerWith(t, Config{})
	var tok struct{ Token string }
	admin.mustJSON("POST", "/api/enroll", map[string]any{"name": "lab", "uses": 5}, &tok)
	agent := newShellAgent(t, ts, tok.Token, "pwbox", "")
	waitFor(t, "agent online", func() bool { return s.hub.IsOnline(agent.id) })

	other := newBrowser(t, ts) // the same account, signed in somewhere else
	other.mustJSON("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password123"}, nil)

	open := func(b *browser) *websocket.Conn {
		c, _, err := websocket.DefaultDialer.Dial(wsURL(ts)+"/ws/shell/"+agent.id, wsCookies(t, ts, b))
		if err != nil {
			t.Fatalf("terminal dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		c.WriteJSON(map[string]any{"t": "open", "shell": "powershell", "cols": 80, "rows": 24})
		if m := readShell(t, c); m["t"] != "opened" {
			t.Fatalf("expected opened, got %v", m)
		}
		return c
	}
	kept, dropped := open(admin), open(other)

	admin.mustJSON("POST", "/api/me/password", map[string]string{"current": "password123", "new": "password456"}, nil)

	dropped.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := dropped.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation {
				t.Fatalf("the other session's terminal ended with %v, want a policy close", err)
			}
			break
		}
	}
	waitFor(t, "one stream left", func() bool { return openStreams(s) == 1 })
	if err := kept.WriteJSON(map[string]any{"t": "resize", "cols": 100, "rows": 30}); err != nil {
		t.Fatalf("the session that changed the password lost its terminal: %v", err)
	}
}

// The event stream filters with the account as it was when the stream
// opened, so it has to end when the account changes or goes away.
func TestEventStreamEndsWhenAccessIsRevoked(t *testing.T) {
	for _, how := range []string{"deleted", "demoted"} {
		t.Run(how, func(t *testing.T) {
			s, ts, admin := newTestServerWith(t, Config{})
			admin.mustJSON("POST", "/api/users", map[string]string{"username": "t1", "password": "password123", "role": "tech"}, nil)
			tech := newBrowser(t, ts)
			tech.mustJSON("POST", "/api/auth/login", map[string]string{"username": "t1", "password": "password123"}, nil)
			id := userID(t, s, "t1")

			resp, err := tech.c.Get(ts.URL + "/api/events")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			rd := bufio.NewReader(resp.Body)
			if line, err := rd.ReadString('\n'); err != nil || !strings.HasPrefix(line, "event: hello") {
				t.Fatalf("stream opened with %q, %v", line, err)
			}
			waitFor(t, "stream tracked", func() bool { return openStreams(s) == 1 })

			if how == "deleted" {
				admin.mustJSON("DELETE", fmt.Sprintf("/api/users/%d", id), nil, nil)
			} else {
				admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", id), map[string]any{"role": "viewer"}, nil)
			}

			ended := make(chan error, 1)
			go func() {
				for {
					if _, err := rd.ReadString('\n'); err != nil {
						ended <- err
						return
					}
				}
			}()
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("the event stream stayed open after the account was " + how)
			}
			waitFor(t, "stream forgotten", func() bool { return openStreams(s) == 0 })
		})
	}
}

// Beginning two-step enrollment must not be a way to remove a factor that is
// in use: turning it off asks for the password, so replacing it must too.
func TestTOTPBeginDoesNotReplaceAnEnabledFactor(t *testing.T) {
	s, ts, b := newTestServerWith(t, Config{})
	var begun struct{ Secret string }
	b.mustJSON("POST", "/api/me/totp/begin", nil, &begun)
	// Beginning again before confirming is still allowed: nothing is enabled.
	b.mustJSON("POST", "/api/me/totp/begin", nil, &begun)
	code, err := totp.GenerateCode(begun.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.mustJSON("POST", "/api/me/totp/confirm", map[string]string{"code": code}, nil)

	state := func() (enabled bool, secret string) {
		if err := s.db.QueryRow(`SELECT totp_enabled, totp_secret FROM users WHERE username = 'admin'`).Scan(&enabled, &secret); err != nil {
			t.Fatal(err)
		}
		return
	}
	if on, _ := state(); !on {
		t.Fatal("two-step sign-in did not turn on")
	}

	st, body := b.do("POST", "/api/me/totp/begin", nil)
	if st != http.StatusConflict {
		t.Fatalf("begin with a factor enabled = %d %s, want 409", st, body)
	}
	if strings.Contains(string(body), "secret") && strings.Contains(string(body), "otpauth") {
		t.Fatalf("the refusal handed out a new secret: %s", body)
	}
	if on, secret := state(); !on || secret != begun.Secret {
		t.Fatalf("after the refused begin: enabled=%v, secret changed=%v", on, secret != begun.Secret)
	}
	// The second factor is still demanded at sign-in.
	loginLimiter.reset("127.0.0.1")
	t.Cleanup(func() { loginLimiter.reset("127.0.0.1") })
	var res struct {
		NeedsTOTP bool `json:"needs_totp"`
	}
	fresh := newBrowser(t, ts)
	fresh.mustJSON("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "password123"}, &res)
	if !res.NeedsTOTP {
		t.Fatal("sign-in no longer asks for the code")
	}

	// The supported way to change it: off with the password, then begin.
	if st, _ := b.do("POST", "/api/me/totp/disable", map[string]string{"password": "wrong-password"}); st != http.StatusForbidden {
		t.Fatalf("disable with a wrong password = %d, want 403", st)
	}
	b.mustJSON("POST", "/api/me/totp/disable", map[string]string{"password": "password123"}, nil)
	var again struct{ Secret string }
	b.mustJSON("POST", "/api/me/totp/begin", nil, &again)
	if again.Secret == "" || again.Secret == begun.Secret {
		t.Fatalf("begin after disabling returned %q", again.Secret)
	}
}

// One account's successful sign-in must not wipe the failures counted
// against other accounts from the same address.
func TestLoginSuccessDoesNotClearOthersFailures(t *testing.T) {
	_, ts, admin := newTestServerWith(t, Config{})
	loginLimiter.reset("127.0.0.1")
	t.Cleanup(func() { loginLimiter.reset("127.0.0.1") })
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "mallory", "password": "password123", "role": "viewer"}, nil)

	guess := func() int {
		st, _ := newBrowser(t, ts).do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "not-the-password"})
		return st
	}
	own := func() int {
		st, _ := newBrowser(t, ts).do("POST", "/api/auth/login", map[string]string{"username": "mallory", "password": "password123"})
		return st
	}

	// Nine guesses, then mallory signs in with her own account. Before, that
	// reset the address and the cycle could repeat without end.
	for i := 0; i < 9; i++ {
		if st := guess(); st != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, st)
		}
	}
	if st := own(); st != http.StatusOK {
		t.Fatalf("mallory's own sign-in = %d, want 200", st)
	}
	// Her success took back only her own attempt: nine failures still count,
	// so the tenth guess is the last one the window allows.
	if st := guess(); st != http.StatusUnauthorized {
		t.Fatalf("tenth guess = %d, want 401", st)
	}
	if st := guess(); st != http.StatusTooManyRequests {
		t.Fatalf("eleventh guess = %d, want 429: a successful sign-in cleared the limit for the whole address", st)
	}
	// And signing in again does not buy more guesses.
	if st := own(); st != http.StatusTooManyRequests {
		t.Fatalf("sign-in from a limited address = %d, want 429", st)
	}
	if st := guess(); st != http.StatusTooManyRequests {
		t.Fatalf("guess after that = %d, want 429", st)
	}
}

// A key stays in the trust bundle until the bundle is rotated. In the
// meantime its owner must not be deletable out from under it, and a demoted
// owner must not go on counting as an approver.
func TestFormerOperatorIsNotCountedAsASigner(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeAudit, 2, 1)
	a1, a2 := f.addAgent("box1"), f.addAgent("box2")
	bob := userID(t, f.s, "bob")
	body := map[string]any{"agent_ids": []string{a1.ID(), a2.ID()}, "language": "bash", "body": "echo hi"}

	// Deleting the account would leave the bundle listing a key nobody owns.
	st, data := f.admin.do("DELETE", fmt.Sprintf("/api/users/%d", bob), nil)
	if st != http.StatusConflict {
		t.Fatalf("deleting a user whose key is in the trust bundle = %d %s, want 409", st, data)
	}
	var keys int
	f.s.db.QueryRow(`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, bob).Scan(&keys)
	if keys != 1 {
		t.Fatalf("bob has %d keys after the refused delete, want 1", keys)
	}

	// Demoting is allowed - it is how access is cut at once - and from then
	// on bob's key does not count, whoever submits its signature.
	f.admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", bob), map[string]any{"role": "viewer"}, nil)

	c := ask(t, f.admin, "POST", "/api/scripts/run", body)
	if st, data := f.admin.doHdr("POST", "/api/scripts/run", body, c.signedBy(t, f.ka)); st != http.StatusAccepted {
		t.Fatalf("first signature = %d %s, want 202", st, data)
	}
	st, data = f.admin.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})})
	if st != http.StatusForbidden {
		t.Fatalf("a demoted operator's signature = %d %s, want 403", st, data)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(a1.requests(protocol.ReqScriptRun)) + len(a2.requests(protocol.ReqScriptRun)); n != 0 {
		t.Fatalf("%d runs dispatched on a former operator's signature", n)
	}

	// Restored, the same signature completes the same request.
	f.admin.mustJSON("PUT", fmt.Sprintf("/api/users/%d", bob), map[string]any{"role": "tech"}, nil)
	st, data = f.admin.do("POST", "/api/approvals/"+c.ManifestID+"/sign", map[string]any{"assertion": f.kb.Sign(c.bytes(t), authtest.SignOpts{})})
	if st != http.StatusOK {
		t.Fatalf("a reinstated operator's signature = %d %s, want 200", st, data)
	}
	a1.wait(protocol.ReqScriptRun, 1)
	a2.wait(protocol.ReqScriptRun, 1)
}

// A user with no key in any bundle is deleted as before.
func TestDeleteUserWithoutBundleKey(t *testing.T) {
	s, _, admin := newTestServerWith(t, Config{})
	admin.mustJSON("POST", "/api/users", map[string]string{"username": "temp", "password": "password123", "role": "tech"}, nil)
	admin.mustJSON("DELETE", fmt.Sprintf("/api/users/%d", userID(t, s, "temp")), nil, nil)
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'temp'`).Scan(&n)
	if n != 0 {
		t.Fatal("the user was not deleted")
	}
}
