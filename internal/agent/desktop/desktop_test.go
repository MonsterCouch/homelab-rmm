package desktop

import (
	"slices"
	"strings"
	"testing"
)

func TestEnvWithToken(t *testing.T) {
	got := envWithToken([]string{"PATH=C:\\Windows", "HOME=C:\\Users\\alice"}, "s3cret")
	if len(got) != 3 || got[2] != TokenEnv+"=s3cret" {
		t.Fatalf("env = %v", got)
	}
	// A variable of the same name inherited from the user's profile must
	// not shadow the token this launch minted, whatever its case.
	got = envWithToken([]string{"PATH=C:\\Windows", "rmm_desktop_token=planted", TokenEnv + "=stale"}, "fresh")
	if len(got) != 2 || got[0] != "PATH=C:\\Windows" || got[1] != TokenEnv+"=fresh" {
		t.Fatalf("env = %v", got)
	}
	// A name that merely starts with the same letters is kept.
	got = envWithToken([]string{TokenEnv + "_EXTRA=keep"}, "t")
	if len(got) != 2 || !slices.Contains(got, TokenEnv+"_EXTRA=keep") {
		t.Fatalf("env = %v", got)
	}
	if strings.Count(strings.Join(got, "\n")+"\n", TokenEnv+"=") != 1 {
		t.Fatalf("token appears more than once: %v", got)
	}
	// The block Windows wants is sorted case-insensitively, so the new
	// entry has to land in order, not at the end.
	got = envWithToken([]string{"=C:=C:\\work", "windir=C:\\Windows", "ALLUSERSPROFILE=C:\\ProgramData"}, "t")
	want := []string{"=C:=C:\\work", "ALLUSERSPROFILE=C:\\ProgramData", TokenEnv + "=t", "windir=C:\\Windows"}
	if !slices.Equal(got, want) {
		t.Fatalf("env = %v want %v", got, want)
	}
}
