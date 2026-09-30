package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The pass request carries the agent key and the account the pipe reported,
// on the route the server serves it from.
func TestRequestPortalPass(t *testing.T) {
	var got struct {
		User        string `json:"user"`
		IsWorkgroup bool   `json:"is_workgroup"`
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/agent/portal-pass" || r.Header.Get("Authorization") != "Bearer agent-key" {
			http.Error(w, "wrong request", http.StatusUnauthorized)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"pass":"p123"}`))
	}))
	defer ts.Close()

	a := New(&Config{ServerURL: ts.URL, Key: "agent-key"})
	pass, err := a.requestPortalPass(context.Background(), `CORP\alice`, false)
	if err != nil {
		t.Fatal(err)
	}
	if pass != "p123" || got.User != `CORP\alice` || got.IsWorkgroup {
		t.Fatalf("pass %q, sent %+v", pass, got)
	}

	a = New(&Config{ServerURL: ts.URL, Key: "wrong"})
	if _, err := a.requestPortalPass(context.Background(), "bob", true); err == nil {
		t.Fatal("a refused pass request reported success")
	}
}
