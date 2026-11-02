package agent

import (
	"strings"
	"testing"
)

// TestChallengerAdversarial_Point1_JSONCredentials tests point 1:
// Confirm JSON-formatted credentials ("password": "...", "token": "...") are properly redacted with 0 leaks.
func TestChallengerAdversarial_Point1_JSONCredentials(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustOmit    []string
		mustContain []string
	}{
		{
			name:        "Standard JSON password",
			input:       `{"user": "alice", "password": "PlainSecretPassword123", "active": true}`,
			mustOmit:    []string{"PlainSecretPassword123"},
			mustContain: []string{`"user": "alice"`, `"password":[REDACTED]`, `"active": true`},
		},
		{
			name:        "Standard JSON token",
			input:       `{"token": "ghp_PersonalAccessTokenABC123XYZ", "scope": "repo"}`,
			mustOmit:    []string{"ghp_PersonalAccessTokenABC123XYZ"},
			mustContain: []string{`"token":[REDACTED]`, `"scope": "repo"`},
		},
		{
			name:        "Standard JSON api_key and secret in same object",
			input:       `{"api_key": "sk-live-0987654321", "secret": "shhh-top-secret-999"}`,
			mustOmit:    []string{"sk-live-0987654321", "shhh-top-secret-999"},
			mustContain: []string{`"api_key":[REDACTED]`, `"secret":[REDACTED]`},
		},
		{
			name:        "Single-quoted JSON/Python style dict",
			input:       `{'password': 'SingleQuotePass456', 'token': 'SingleQuoteTok789'}`,
			mustOmit:    []string{"SingleQuotePass456", "SingleQuoteTok789"},
			mustContain: []string{`'password':[REDACTED]`, `'token':[REDACTED]`},
		},
		{
			name:        "JSON with spaces and tabs around colon",
			input:       "{\n  \"password\" \t : \t \"TabbedSecretPassword000\"\n}",
			mustOmit:    []string{"TabbedSecretPassword000"},
			mustContain: []string{`"password":[REDACTED]`},
		},
		{
			name:        "Numeric unquoted token in JSON",
			input:       `{"token": 987654321, "status": "ok"}`,
			mustOmit:    []string{"987654321"},
			mustContain: []string{`"token":[REDACTED]`, `"status": "ok"`},
		},
		{
			name:        "Empty string password in JSON",
			input:       `{"password": "", "user": "guest"}`,
			mustOmit:    []string{},
			mustContain: []string{`"password":[REDACTED]`, `"user": "guest"`},
		},
		{
			name:        "Nested JSON object",
			input:       `{"database": {"host": "10.0.0.1", "password": "DbNestedSecretPassword777"}, "port": 5432}`,
			mustOmit:    []string{"DbNestedSecretPassword777"},
			mustContain: []string{`"host": "10.0.0.1"`, `"password":[REDACTED]`, `"port": 5432`},
		},
		{
			name:        "JSON array of objects containing secrets",
			input:       `[{"token": "tokItemOne111"}, {"user": "bob"}, {"password": "passItemTwo222"}]`,
			mustOmit:    []string{"tokItemOne111", "passItemTwo222"},
			mustContain: []string{`"token":[REDACTED]`, `"user": "bob"`, `"password":[REDACTED]`},
		},
		{
			name:        "JSON with newline between colon and value",
			input:       "{\"password\":\n\"NewlineVal333\"}",
			mustOmit:    []string{"NewlineVal333"},
			mustContain: []string{`"password":[REDACTED]`},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			for _, sec := range tc.mustOmit {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK in %s: secret %q leaked in output: %s", tc.name, sec, actual)
				}
			}
			for _, exp := range tc.mustContain {
				if !strings.Contains(actual, exp) {
					t.Fatalf("EXPECTED SUBSTRING MISSING in %s: expected %q, got: %s", tc.name, exp, actual)
				}
			}
		})
	}
}

// TestChallengerAdversarial_Point2_MultiWordQuotedSecrets tests point 2:
// Confirm multi-word quoted secrets (password="A B C") do not leak following words.
func TestChallengerAdversarial_Point2_MultiWordQuotedSecrets(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustOmit    []string
		mustContain []string
	}{
		{
			name:        "Three words double quotes",
			input:       `password="A B C" trailing_param=normal`,
			mustOmit:    []string{"A B C", "B C", " C"},
			mustContain: []string{"password=[REDACTED]", "trailing_param=normal"},
		},
		{
			name:        "Three words single quotes",
			input:       `password='A B C' trailing_param=normal`,
			mustOmit:    []string{"A B C", "B C", " C"},
			mustContain: []string{"password=[REDACTED]", "trailing_param=normal"},
		},
		{
			name:        "Sentence secret with punctuation",
			input:       `api_key="Correct Horse Battery Staple! 2026" next=true`,
			mustOmit:    []string{"Correct Horse Battery Staple! 2026", "Horse Battery", "Battery Staple"},
			mustContain: []string{"api_key=[REDACTED]", "next=true"},
		},
		{
			name:        "Multi-word secret followed immediately by another secret",
			input:       `password="Word One Two" token="Tok Three Four"`,
			mustOmit:    []string{"Word One Two", "One Two", "Tok Three Four", "Three Four"},
			mustContain: []string{"password=[REDACTED]", "token=[REDACTED]"},
		},
		{
			name:        "Colon delimiter with multi-word quoted secret",
			input:       `secret : "Secret Multi Word With Spaces 123" ; log=done`,
			mustOmit:    []string{"Secret Multi Word With Spaces 123", "Multi Word", "With Spaces"},
			mustContain: []string{"secret:[REDACTED]", "log=done"},
		},
		{
			name:        "Quoted secret with special characters inside",
			input:       `passwd="Pass with !@#$%^&*()_+ and spaces" tail=ok`,
			mustOmit:    []string{"Pass with !@#$%^&*()_+ and spaces", "!@#$%^&*()_+"},
			mustContain: []string{"passwd=[REDACTED]", "tail=ok"},
		},
		{
			name:        "Empty quoted value",
			input:       `password="" other=foo`,
			mustOmit:    []string{},
			mustContain: []string{"password=[REDACTED]", "other=foo"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			for _, sec := range tc.mustOmit {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK in %s: word/secret %q leaked in output: %s", tc.name, sec, actual)
				}
			}
			for _, exp := range tc.mustContain {
				if !strings.Contains(actual, exp) {
					t.Fatalf("EXPECTED SUBSTRING MISSING in %s: expected %q, got: %s", tc.name, exp, actual)
				}
			}
		})
	}
}

// TestChallengerAdversarial_Point3_EnglishProsePreservation tests point 3:
// Confirm English prose ("bearer of bad news") is preserved without false positive redactions.
func TestChallengerAdversarial_Point3_EnglishProsePreservation(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "bearer of bad news",
			input: "He was the bearer of bad news regarding the server outage.",
		},
		{
			name:  "bearer must present ID",
			input: "The bearer must present proper credentials at the security checkpoint.",
		},
		{
			name:  "bearer bonds",
			input: "The company holds bearer bonds in its vault.",
		},
		{
			name:  "bearer certificate",
			input: "A bearer certificate of deposit was issued by the bank.",
		},
		{
			name:  "bearer shares",
			input: "Bearer shares are prohibited in modern jurisdictions.",
		},
		{
			name:  "bearer instrument",
			input: "A check payable to cash is a bearer instrument payable on demand.",
		},
		{
			name:  "bearer friend mid-sentence",
			input: "The bearer person entered with the bearer friend to verify the account.",
		},
		{
			name:  "bearer will deliver",
			input: "The message bearer will arrive before sunset.",
		},
		{
			name:  "bearer shall comply",
			input: "The bearer shall comply with all station regulations.",
		},
		{
			name:  "bearer who arrived",
			input: "The bearer who delivered the parcel has left.",
		},
		{
			name:  "bearer is authorized",
			input: "Only if the bearer is authorized may they enter.",
		},
		{
			name:  "bearer was detained",
			input: "The bearer was detained at the perimeter.",
		},
		{
			name:  "bearer has left",
			input: "The bearer has departed the premises.",
		},
		{
			name:  "bearer can sign",
			input: "The bearer can acknowledge receipt directly.",
		},
		{
			name:  "bearer may proceed",
			input: "The bearer may proceed to terminal 4.",
		},
		{
			name:  "bearer with authorization",
			input: "Any bearer with clearance may view the document.",
		},
		{
			name:  "talebearer or shieldbearer compound words",
			input: "The talebearer spread rumors while the armor-bearer stood guard.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if strings.Contains(actual, "[REDACTED]") {
				t.Fatalf("FALSE POSITIVE in %s: prose was redacted!\nInput:  %s\nOutput: %s",
					tc.name, tc.input, actual)
			}
			if actual != tc.input {
				t.Fatalf("TEXT MUTATION in %s:\nExpected: %s\nActual:   %s",
					tc.name, tc.input, actual)
			}
		})
	}
}

// TestChallengerAdversarial_Point4_URLQueryParameters tests point 4:
// Confirm URL query parameters (token=abc&user=admin) preserve unredacted parameters.
func TestChallengerAdversarial_Point4_URLQueryParameters(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		mustOmit    []string
		mustContain []string
	}{
		{
			name:        "Token first, followed by user",
			input:       "GET /auth?token=SecretTokenVal123&user=admin HTTP/1.1",
			mustOmit:    []string{"SecretTokenVal123"},
			mustContain: []string{"token=[REDACTED]", "&user=admin"},
		},
		{
			name:        "User first, followed by token",
			input:       "https://rmm.local/api/v1?user=operator&token=SecretTokenVal456",
			mustOmit:    []string{"SecretTokenVal456"},
			mustContain: []string{"user=operator&", "token=[REDACTED]"},
		},
		{
			name:        "Token between unredacted params",
			input:       "https://rmm.local/endpoint?scope=read&token=SecretTokenVal789&format=json&version=2",
			mustOmit:    []string{"SecretTokenVal789"},
			mustContain: []string{"scope=read&", "token=[REDACTED]", "&format=json&version=2"},
		},
		{
			name:        "Multiple sensitive params in query string",
			input:       "https://api.internal/login?user=admin&password=SecretPass999&api_key=SecretKey888&debug=false",
			mustOmit:    []string{"SecretPass999", "SecretKey888"},
			mustContain: []string{"user=admin&", "password=[REDACTED]", "&api_key=[REDACTED]", "&debug=false"},
		},
		{
			name:        "URL with fragment / hash",
			input:       "https://api.internal/connect?token=MySecretToken111&env=prod#section2",
			mustOmit:    []string{"MySecretToken111"},
			mustContain: []string{"token=[REDACTED]", "&env=prod#section2"},
		},
		{
			name:        "Semicolon-delimited query string",
			input:       "https://api.internal/query;token=SemiTokenSecret222;session=valid;role=admin",
			mustOmit:    []string{"SemiTokenSecret222"},
			mustContain: []string{"token=[REDACTED]", ";session=valid;role=admin"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			for _, sec := range tc.mustOmit {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK in %s: secret %q leaked in output: %s", tc.name, sec, actual)
				}
			}
			for _, exp := range tc.mustContain {
				if !strings.Contains(actual, exp) {
					t.Fatalf("EXPECTED SUBSTRING MISSING in %s: expected %q, got: %s", tc.name, exp, actual)
				}
			}
		})
	}
}
