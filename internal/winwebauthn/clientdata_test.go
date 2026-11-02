package winwebauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestClientDataJSONExactBytes(t *testing.T) {
	// 0xfb 0xff encodes to "-_8" in base64url and "+/8=" in the standard
	// alphabet, which proves both the alphabet and the missing padding.
	got := string(ClientDataJSON([]byte{0xfb, 0xff}, "https://rmm.example.com"))
	want := `{"type":"webauthn.get","challenge":"-_8","origin":"https://rmm.example.com","crossOrigin":false}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestClientDataJSONRoundTrip(t *testing.T) {
	challenge := []byte(`{"v":1,"kind":"script.run"}`)
	origin := `https://host.example:8443`
	raw := ClientDataJSON(challenge, origin)
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	dec, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || string(dec) != string(challenge) {
		t.Fatalf("challenge did not round-trip: %q, %v", dec, err)
	}
	if cd.Type != "webauthn.get" || cd.Origin != origin || cd.CrossOrigin {
		t.Fatalf("unexpected fields: %+v", cd)
	}
}

func TestClientDataJSONEscapesOrigin(t *testing.T) {
	got := string(ClientDataJSON([]byte{1}, `https://a"b&c`))
	want := `{"type":"webauthn.get","challenge":"AQ","origin":"https://a\"b&c","crossOrigin":false}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		hr   uint32
		want error
	}{
		{hrErrorCancelled, ErrCancelled},
		{hrUserCancelled, ErrCancelled},
		{hrErrorTimeout, ErrTimeout},
		{hrNotFound, ErrNoCredentials},
		{hrDeviceNotFound, ErrNoCredentials},
	}
	for _, c := range cases {
		err := error(&Error{Func: "f", HResult: c.hr, Name: "NotAllowedError"})
		if !errors.Is(err, c.want) {
			t.Errorf("HRESULT 0x%08X does not match %v", c.hr, c.want)
		}
	}
	other := error(&Error{Func: "f", HResult: hrErrorTimeout})
	if errors.Is(other, ErrCancelled) {
		t.Error("a timeout matched ErrCancelled")
	}
	if msg := (&Error{Func: "f", HResult: 0x80004005}).Error(); msg == "" {
		t.Error("empty message for an unknown HRESULT")
	}
}
