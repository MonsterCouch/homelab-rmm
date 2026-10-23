package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
)

// runTrust is the `trust` subcommand. Its one job, sign-bundle, is the offline
// half of recovery: when every security key is lost, the recovery key (kept
// off the server and off the operator's browser) signs a replacement trust
// bundle, and the signature goes to POST /api/trust/proposals/{pid}/recovery.
// It touches no database and no network on purpose, so it can run on a
// machine that has never seen the server.
func runTrust(args []string) int {
	if len(args) == 0 || args[0] != "sign-bundle" {
		usage()
		return 2
	}
	fs := flag.NewFlagSet("trust sign-bundle", flag.ExitOnError)
	fs.Usage = usage
	keyFile := fs.String("key", "", "file holding the recovery key (rmm-recovery-v1:...)")
	bundleFile := fs.String("bundle", "", "file holding the proposal's base64url \"bundle\" field")
	out := fs.String("out", "", "write the signature JSON here instead of stdout")
	fs.Parse(args[1:])
	if *keyFile == "" || *bundleFile == "" {
		fmt.Fprintln(os.Stderr, "--key and --bundle are required")
		return 2
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	bundle, err := os.ReadFile(*bundleFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sig, err := signBundle(string(key), string(bundle))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *out != "" {
		if err := os.WriteFile(*out, append(sig, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	fmt.Println(string(sig))
	return 0
}

// signBundle returns {"id", "sig"} for the recovery endpoint: the key's ID
// and its Ed25519 signature over the exact bundle bytes. keyText is
// RecoveryKeyPrefix + the base64url 32-byte seed; bundleText the base64url
// bundle.
func signBundle(keyText, bundleText string) ([]byte, error) {
	seedText, ok := strings.CutPrefix(strings.TrimSpace(keyText), actionauth.RecoveryKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("the key does not start with %q; is this a recovery key file?", actionauth.RecoveryKeyPrefix)
	}
	seed, err := decodeB64(seedText)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the recovery key is damaged: expected a base64url 32-byte seed")
	}
	bundle, err := decodeB64(bundleText)
	if err != nil || len(bundle) == 0 {
		return nil, errors.New("the bundle file is not the base64url \"bundle\" field of the proposal")
	}
	// This key can replace the fleet's root of trust, so it signs only bytes
	// that an agent would accept as a bundle.
	if _, err := actionauth.ParseBundle(bundle); err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return json.Marshal(map[string]string{
		"id":  actionauth.RecoveryKeyID(priv.Public().(ed25519.PublicKey)),
		"sig": actionauth.EncodeB64(ed25519.Sign(priv, bundle)),
	})
}

// decodeB64 reads unpadded base64url and tolerates padding and surrounding
// whitespace (a key or bundle pasted into a file usually ends in a newline).
func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
}
