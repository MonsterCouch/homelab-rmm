package winwebauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// ClientDataJSON builds the collected client data the way a browser does for
// navigator.credentials.get: type, challenge (base64url, no padding), origin and
// crossOrigin, in that order. The assertion signs the SHA-256 of exactly these
// bytes and the verifier hashes whatever it is sent, so the bytes returned here
// are the ones that must be posted back.
func ClientDataJSON(challenge []byte, origin string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"type":"webauthn.get","challenge":"`)
	b.WriteString(base64.RawURLEncoding.EncodeToString(challenge))
	b.WriteString(`","origin":`)
	b.Write(jsonString(origin))
	b.WriteString(`,"crossOrigin":false}`)
	return b.Bytes()
}

// jsonString quotes s without HTML escaping, so an origin never contains
// escapes that differ from what a browser would produce.
func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return bytes.TrimRight(b.Bytes(), "\n")
}
