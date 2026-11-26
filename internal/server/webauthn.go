package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
)

// Security keys (WebAuthn credentials), the signing identities of Phase 3
// (docs/plans/2026-10-06-phase3-signed-actions.md, 4.1).
//
// Registration needs no CBOR library: the browser hands over the public key as
// SubjectPublicKeyInfo (response.getPublicKey()), which is also the form the
// trust bundle carries, so the attestation object is never parsed. The server
// asks for attestation "none" and does not look at the attested credential
// data. What registration must prove is only that the browser, on an origin
// the bundle will name, created the key for this relying party and this
// challenge; the key's own signatures are checked later, by every agent,
// against the bundle.

const (
	registerChallengeTTL = 5 * time.Minute
	maxCredsPerUser      = 20
	maxCredentialIDLen   = 1023 // WebAuthn's own limit on a credential ID
)

// regChallenges holds the single outstanding registration challenge per user,
// in memory: it is single use and short lived, and a restart only costs the
// operator one more click.
type regChallenges struct {
	mu      sync.Mutex
	pending map[int64]regChallenge
}

type regChallenge struct {
	challenge []byte
	expires   time.Time
}

func (c *regChallenges) put(userID int64, ch []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = map[int64]regChallenge{}
	}
	now := time.Now()
	for id, p := range c.pending { // bounded by the number of users; sweep as we go
		if now.After(p.expires) {
			delete(c.pending, id)
		}
	}
	c.pending[userID] = regChallenge{challenge: ch, expires: now.Add(registerChallengeTTL)}
}

// take returns and removes the user's pending challenge. It is consumed by the
// first finish attempt, successful or not: a challenge that survived a failed
// attempt could be ground against.
func (c *regChallenges) take(userID int64) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[userID]
	delete(c.pending, userID)
	if !ok || time.Now().After(p.expires) {
		return nil, false
	}
	return p.challenge, true
}

// errIPRelyingParty is what registration says when the console is reached by
// an address: browsers refuse an IP address as an RP ID, so nothing could be
// registered or signed.
var errIPRelyingParty = errors.New("security keys need the console to be reached by a DNS name, not an IP address; set RMM_PUBLIC_URL or RMM_WEBAUTHN_RP_ID")

// webauthnRP is the relying party the trust bundle will pin: the RP ID and the
// origins browsers will report. They come from the public URL unless the
// operator pinned them, and are read per call because the public URL is
// editable in Settings.
func (s *Server) webauthnRP() (rpID string, origins []string, err error) {
	u, perr := url.Parse(s.PublicURL())
	if perr != nil || u.Hostname() == "" {
		return "", nil, errors.New("the public URL is not a valid URL; set RMM_PUBLIC_URL")
	}
	rpID = strings.ToLower(u.Hostname())
	if s.cfg.WebAuthnRPID != "" {
		rpID = strings.ToLower(strings.TrimSpace(s.cfg.WebAuthnRPID))
	}
	if net.ParseIP(strings.Trim(rpID, "[]")) != nil {
		return "", nil, errIPRelyingParty
	}
	if len(s.cfg.WebAuthnOrigins) > 0 {
		for _, o := range s.cfg.WebAuthnOrigins {
			ou, oerr := url.Parse(strings.TrimSpace(o))
			if oerr != nil || ou.Scheme == "" || ou.Host == "" {
				return "", nil, fmt.Errorf("RMM_WEBAUTHN_ORIGINS entry %q is not scheme://host[:port]", o)
			}
			origins = append(origins, canonicalOrigin(ou))
		}
		return rpID, origins, nil
	}
	return rpID, []string{canonicalOrigin(u)}, nil
}

// canonicalOrigin renders scheme://host[:port] the way a browser reports it:
// lower case, and without the scheme's default port.
func canonicalOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// userHandle is the stable, opaque WebAuthn user ID. It is derived from the
// row ID and creation time rather than stored: SQLite reuses the highest row
// ID after a delete, and two accounts sharing a handle would let one's
// registration replace the other's discoverable credential on a key.
func userHandle(u *User) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("rmm-webauthn-user:%d:%d", u.ID, u.CreatedAt)))
	return actionauth.EncodeB64(h[:16])
}

// ---- storage ----

// Credential is a registered security key as the console sees it.
type Credential struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Alg        int      `json:"alg"`
	Owner      string   `json:"owner"`
	CreatedAt  int64    `json:"created_at"`
	LastUsedAt int64    `json:"last_used_at"`
	InBundle   bool     `json:"in_bundle"`
	BundleOrgs []string `json:"bundle_orgs,omitempty"`

	publicKey []byte
	userID    int64
}

func (d *DB) listCredentials(userID int64, all bool) ([]Credential, error) {
	q := `SELECT c.id, c.name, c.alg, u.username, c.created_at, c.last_used_at, c.public_key, c.user_id
		FROM webauthn_credentials c JOIN users u ON u.id = c.user_id`
	args := []any{}
	if !all {
		q += ` WHERE c.user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY u.username, c.created_at, c.id`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Name, &c.Alg, &c.Owner, &c.CreatedAt, &c.LastUsedAt, &c.publicKey, &c.userID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) getCredential(id string) (*Credential, error) {
	var c Credential
	err := d.QueryRow(`SELECT c.id, c.name, c.alg, u.username, c.created_at, c.last_used_at, c.public_key, c.user_id
		FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE c.id = ?`, id).
		Scan(&c.ID, &c.Name, &c.Alg, &c.Owner, &c.CreatedAt, &c.LastUsedAt, &c.publicKey, &c.userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return &c, err
}

// bundleCredentials maps each credential ID to the organizations whose
// CURRENT trust bundle lists it.
func (d *DB) bundleCredentials() (map[string][]string, error) {
	rows, err := d.Query(`SELECT t.org_id, t.bundle FROM trust_bundles t
		WHERE t.epoch = (SELECT MAX(epoch) FROM trust_bundles WHERE org_id = t.org_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var org string
		var raw []byte
		if err := rows.Scan(&org, &raw); err != nil {
			return nil, err
		}
		var b actionauth.Bundle
		if json.Unmarshal(raw, &b) != nil {
			continue
		}
		for _, sg := range b.Signers {
			for _, c := range sg.Creds {
				out[c.ID] = append(out[c.ID], org)
			}
		}
	}
	return out, rows.Err()
}

// bundleKeysOf reports whether any security key of the user is listed in a
// current trust bundle.
func (d *DB) bundleKeysOf(userID int64) (bool, error) {
	inBundle, err := d.bundleCredentials()
	if err != nil {
		return false, err
	}
	rows, err := d.Query(`SELECT id FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		if len(inBundle[id]) > 0 {
			return true, nil
		}
	}
	return false, rows.Err()
}

// signerIsLive reports whether the key behind an assertion still belongs to
// an account that may operate devices. Agents verify against the trust
// bundle, and the bundle only changes by a signed rotation, so a key stays in
// it after its owner is demoted (or, before deletion was guarded, deleted).
// Until the bundle is rotated the server is the one place that can refuse to
// count that key, and it must: otherwise a former operator still completes a
// two-person approval that any remaining technician submits for them.
func (d *DB) signerIsLive(credID, owner string) bool {
	if raw, err := b64dec(credID); err == nil {
		credID = actionauth.EncodeB64(raw)
	}
	var username, role string
	err := d.QueryRow(`SELECT u.username, u.role FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE c.id = ?`, credID).
		Scan(&username, &role)
	if err != nil {
		return false
	}
	return username == owner && (&User{Base: d.resolveRole(role).Base}).CanWrite()
}

func markInBundle(creds []Credential, inBundle map[string][]string) {
	for i := range creds {
		if orgs := inBundle[creds[i].ID]; len(orgs) > 0 {
			creds[i].InBundle = true
			sort.Strings(orgs)
			creds[i].BundleOrgs = orgs
		}
	}
}

// ---- handlers ----

// handleWebAuthnBegin returns PublicKeyCredentialCreationOptions.
func (s *Server) handleWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	rpID, _, err := s.webauthnRP()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.db.listCredentials(u.ID, false)
	if err != nil {
		fail(w, err)
		return
	}
	if len(existing) >= maxCredsPerUser {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("an account may register at most %d security keys", maxCredsPerUser))
		return
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		fail(w, err)
		return
	}
	s.regs.put(u.ID, challenge)

	type descriptor struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	exclude := make([]descriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, descriptor{Type: "public-key", ID: c.ID})
	}
	writeJSON(w, 200, map[string]any{
		"challenge": actionauth.EncodeB64(challenge),
		"rp":        map[string]string{"id": rpID, "name": "Homelab RMM"},
		"user":      map[string]string{"id": userHandle(u), "name": u.Username, "displayName": u.Username},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": actionauth.AlgES256},
			{"type": "public-key", "alg": actionauth.AlgEdDSA},
			{"type": "public-key", "alg": actionauth.AlgRS256},
		},
		"timeout":     60000,
		"attestation": "none",
		"authenticatorSelection": map[string]string{
			"residentKey":      "preferred",
			"userVerification": "preferred",
		},
		"excludeCredentials": exclude,
	})
}

type registerFinishIn struct {
	Name               string `json:"name"`
	ID                 string `json:"id"`
	ClientDataJSON     string `json:"clientDataJSON"`
	AuthenticatorData  string `json:"authenticatorData"`
	PublicKey          string `json:"publicKey"`
	PublicKeyAlgorithm int    `json:"publicKeyAlgorithm"`
}

// b64 decodes unpadded base64url and tolerates padding, as the bundle code
// does: browsers' helpers differ.
func b64dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (s *Server) handleWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	var in registerFinishIn
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	rpID, origins, err := s.webauthnRP()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	challenge, ok := s.regs.take(u.ID)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no registration is in progress (it may have expired); start again")
		return
	}
	cred, err := verifyRegistration(in, challenge, rpID, origins)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	existing, err := s.db.listCredentials(u.ID, false)
	if err != nil {
		fail(w, err)
		return
	}
	if len(existing) >= maxCredsPerUser {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("an account may register at most %d security keys", maxCredsPerUser))
		return
	}
	if _, err := s.db.getCredential(cred.ID); err == nil {
		writeErr(w, http.StatusConflict, "that security key is already registered")
		return
	}
	cred.Name = strings.TrimSpace(in.Name)
	if cred.Name == "" {
		cred.Name = "Security key"
	}
	if len(cred.Name) > 64 {
		cred.Name = cred.Name[:64]
	}
	cred.CreatedAt = now()
	if _, err := s.db.Exec(`INSERT INTO webauthn_credentials(id, user_id, name, alg, public_key, created_at) VALUES(?,?,?,?,?,?)`,
		cred.ID, u.ID, cred.Name, cred.Alg, cred.publicKey, cred.CreatedAt); err != nil {
		fail(w, err)
		return
	}
	cred.Owner = u.Username
	s.audit(r, "webauthn.register", cred.ID, map[string]any{"name": cred.Name, "alg": cred.Alg})
	writeJSON(w, 201, cred)
}

// verifyRegistration checks a browser's registration response against the
// challenge the server issued and returns the credential to store. It is
// separate from the handler so each rejection is a plain function result.
func verifyRegistration(in registerFinishIn, challenge []byte, rpID string, origins []string) (*Credential, error) {
	id, err := b64dec(in.ID)
	if err != nil || len(id) == 0 || len(id) > maxCredentialIDLen {
		return nil, errors.New("credential id is not valid base64url")
	}
	cdRaw, err := b64dec(in.ClientDataJSON)
	if err != nil {
		return nil, errors.New("clientDataJSON is not base64url")
	}
	ad, err := b64dec(in.AuthenticatorData)
	if err != nil {
		return nil, errors.New("authenticatorData is not base64url")
	}
	der, err := b64dec(in.PublicKey)
	if err != nil || len(der) == 0 {
		return nil, errors.New("publicKey is not base64url")
	}

	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(cdRaw, &cd); err != nil {
		return nil, errors.New("clientDataJSON is not JSON")
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("clientData type %q is not webauthn.create", cd.Type)
	}
	got, err := b64dec(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return nil, errors.New("the registration was made for a different challenge")
	}
	if cd.CrossOrigin {
		return nil, errors.New("cross-origin registration is refused")
	}
	trusted := false
	for _, o := range origins {
		if strings.TrimRight(cd.Origin, "/") == o {
			trusted = true
		}
	}
	if !trusted {
		return nil, fmt.Errorf("origin %q is not one this console is served from", cd.Origin)
	}

	// authenticatorData: rpIdHash(32) | flags(1) | signCount(4) | attested data
	if len(ad) < 37 {
		return nil, errors.New("authenticatorData is too short")
	}
	rp := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(ad[:32], rp[:]) != 1 {
		return nil, errors.New("the key was created for a different relying party")
	}
	if ad[32]&0x01 == 0 {
		return nil, errors.New("user presence was not asserted")
	}

	if err := checkSPKI(in.PublicKeyAlgorithm, der); err != nil {
		return nil, err
	}
	return &Credential{ID: actionauth.EncodeB64(id), Alg: in.PublicKeyAlgorithm, publicKey: der}, nil
}

// checkSPKI requires the key to parse and to be the kind its algorithm
// names, the same rules an agent applies when it loads a bundle, so a key
// that registers here can always be put in a bundle.
func checkSPKI(alg int, der []byte) error {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	switch alg {
	case actionauth.AlgES256:
		if k, ok := pub.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
			return errors.New("ES256 needs a P-256 ECDSA key")
		}
	case actionauth.AlgEdDSA:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return errors.New("EdDSA needs an Ed25519 key")
		}
	case actionauth.AlgRS256:
		if k, ok := pub.(*rsa.PublicKey); !ok || k.N.BitLen() < 2048 {
			return errors.New("RS256 needs an RSA key of at least 2048 bits")
		}
	default:
		return fmt.Errorf("unsupported public key algorithm %d", alg)
	}
	return nil
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	creds, err := s.db.listCredentials(u.ID, u.IsAdmin())
	if err != nil {
		fail(w, err)
		return
	}
	inBundle, err := s.db.bundleCredentials()
	if err != nil {
		fail(w, err)
		return
	}
	markInBundle(creds, inBundle)
	writeJSON(w, 200, creds)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	c, err := s.db.getCredential(id)
	// A key that is not yours is "not found", not "forbidden": whether
	// another operator has a given credential is not for you to probe.
	if err != nil || (c.userID != u.ID && !u.IsAdmin()) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	inBundle, err := s.db.bundleCredentials()
	if err != nil {
		fail(w, err)
		return
	}
	if len(inBundle[c.ID]) > 0 {
		writeErr(w, http.StatusConflict, "this key is in a trust bundle that agents rely on: remove it from the trust bundle first")
		return
	}
	if _, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ?`, c.ID); err != nil {
		fail(w, err)
		return
	}
	s.audit(r, "webauthn.delete", c.ID, map[string]any{"name": c.Name, "owner": c.Owner})
	writeJSON(w, 200, map[string]any{"ok": true})
}
