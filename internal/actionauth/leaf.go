package actionauth

import (
	"encoding/json"
	"errors"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// ManifestLeaf returns the transparency log leaf for a released manifest:
// canonical JSON of {"kind":"manifest","manifest":<b64>,"sigs":[...]}. The
// server builds it when it logs the manifest and the agent rebuilds it from
// the ActionAuth it received, so both must produce identical bytes.
func ManifestLeaf(auth *protocol.ActionAuth) ([]byte, error) {
	if auth == nil || auth.M == "" {
		return nil, errors.New("a manifest log leaf needs a manifest and its signatures")
	}
	sigs := auth.S
	if sigs == nil {
		sigs = []protocol.Assertion{}
	}
	raw, err := json.Marshal(struct {
		Kind     string               `json:"kind"`
		Manifest string               `json:"manifest"`
		Sigs     []protocol.Assertion `json:"sigs"`
	}{"manifest", auth.M, sigs})
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(raw)
}
