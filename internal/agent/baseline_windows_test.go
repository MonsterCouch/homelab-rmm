//go:build windows

package agent

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// These exercise the Windows-only pure helpers of the baseline kinds. They
// cannot run on the Linux build box, but `GOOS=windows go vet` type-checks
// them against x/sys/windows/registry, which is where the value types come
// from.

// A check's declared type is the type the value must be STORED as. The x/sys
// getters answer for more than one REG_* type each, so without this a `dword`
// check would read a REG_QWORD (and compare its low 32 bits) and a `string`
// check would read a REG_EXPAND_SZ.
func TestWinRegTypesAreNotInterchangeable(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want uint32
	}{
		{"dword", registry.DWORD},
		{"qword", registry.QWORD},
		{"string", registry.SZ},
		{"expand_string", registry.EXPAND_SZ},
		{"multi_string", registry.MULTI_SZ},
	} {
		got, ok := winRegValueType(tc.kind)
		if !ok || got != tc.want {
			t.Errorf("%s maps to %v (%v), want %v", tc.kind, got, ok, tc.want)
		}
		if err := winRegTypeMismatch(tc.kind, tc.want, tc.want); err != nil {
			t.Errorf("%s against its own stored type is not a mismatch: %v", tc.kind, err)
		}
	}
	if _, ok := winRegValueType("binary"); ok {
		t.Fatal("only the five declared types are readable")
	}
	// The pairs the getters would otherwise let through.
	for _, tc := range []struct {
		kind      string
		want, got uint32
		names     []string
	}{
		{"dword", registry.DWORD, registry.QWORD, []string{"dword", "REG_DWORD", "REG_QWORD"}},
		{"qword", registry.QWORD, registry.DWORD, []string{"qword", "REG_QWORD", "REG_DWORD"}},
		{"string", registry.SZ, registry.EXPAND_SZ, []string{"string", "REG_SZ", "REG_EXPAND_SZ"}},
		{"expand_string", registry.EXPAND_SZ, registry.SZ, []string{"expand_string", "REG_EXPAND_SZ", "REG_SZ"}},
		{"multi_string", registry.MULTI_SZ, registry.SZ, []string{"multi_string", "REG_MULTI_SZ", "REG_SZ"}},
	} {
		err := winRegTypeMismatch(tc.kind, tc.want, tc.got)
		if err == nil {
			t.Fatalf("%s must not read a %s", tc.kind, winRegTypeName(tc.got))
		}
		for _, n := range tc.names {
			if !strings.Contains(err.Error(), n) {
				t.Errorf("%s vs %s: the error must name %q, got %q", tc.kind, winRegTypeName(tc.got), n, err)
			}
		}
	}
	if winRegTypeName(registry.BINARY) != "REG_BINARY" || !strings.Contains(winRegTypeName(9999), "9999") {
		t.Fatal("every stored type has a name an operator can read")
	}
}

// Get-WindowsOptionalFeature returns $null for a name no feature has - it does
// not throw - so the script has to test $f before it reads $f.State, or the
// detail an operator sees is "You cannot call a method on a null-valued
// expression" with no mention of the feature.
func TestWinFeatureQueryScriptGuardsAMissingFeature(t *testing.T) {
	guard := strings.Index(winFeatureQueryScript, "$null -eq $f")
	deref := strings.Index(winFeatureQueryScript, "$f.State")
	switch {
	case guard < 0:
		t.Fatal("the query script must test $f against $null")
	case deref < 0:
		t.Fatal("the query script must still read the feature state")
	case guard > deref:
		t.Fatal("the $null guard must come before $f is dereferenced")
	}
	if !strings.Contains(winFeatureQueryScript, "no optional feature named") {
		t.Fatal("the missing-feature message must say what was not found")
	}
	if !strings.Contains(winFeatureQueryScript, "$Name") {
		t.Fatal("the missing-feature message must name the feature the check asked for")
	}
}
