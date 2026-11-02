package agent

import (
	"strings"
	"testing"
)

// ============================================================================
// Area 1: Bearer Token Redaction
// ============================================================================

func TestBearerTokenRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		{
			name:     "Standard JWT Bearer token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcbeZrQzzz",
			expected: "Authorization: Bearer [REDACTED]",
			secrets:  []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcbeZrQzzz"},
		},
		{
			name:     "Opaque Bearer token with punctuation and double equals padding",
			input:    "Connecting with Bearer ya29.a0AfH6SMB_xyz-123~+/== to cloud API",
			expected: "Connecting with Bearer [REDACTED] to cloud API",
			secrets:  []string{"ya29.a0AfH6SMB_xyz-123~+/=="},
		},
		{
			name:     "Bearer token with single equal padding",
			input:    "Header: Bearer dGVzdF90b2tlbl92YWx1ZQ=",
			expected: "Header: Bearer [REDACTED]",
			secrets:  []string{"dGVzdF90b2tlbl92YWx1ZQ="},
		},
		{
			name:     "Bearer token with double equal padding",
			input:    "Header: Bearer dGVzdF90b2tlbg==",
			expected: "Header: Bearer [REDACTED]",
			secrets:  []string{"dGVzdF90b2tlbg=="},
		},
		{
			name:     "Alphanumeric Bearer token",
			input:    "Bearer abcd1234EFGH5678",
			expected: "Bearer [REDACTED]",
			secrets:  []string{"abcd1234EFGH5678"},
		},
		{
			name:     "Multiple Bearer tokens in one line",
			input:    "Token 1: Bearer token_one_12345; Token 2: Bearer token_two_67890",
			expected: "Token 1: Bearer [REDACTED]; Token 2: Bearer [REDACTED]",
			secrets:  []string{"token_one_12345", "token_two_67890"},
		},
		{
			name:     "Bearer token with multiple spaces",
			input:    "Headers: Bearer   sk_test_abc123xyz456",
			expected: "Headers: Bearer [REDACTED]",
			secrets:  []string{"sk_test_abc123xyz456"},
		},
		{
			name:     "Bearer token with tab separation",
			input:    "Headers: Bearer\tsk_test_tab_token",
			expected: "Headers: Bearer [REDACTED]",
			secrets:  []string{"sk_test_tab_token"},
		},
		{
			name:     "Bare Bearer prefix at start of line",
			input:    "Bearer secretTokenVal",
			expected: "Bearer [REDACTED]",
			secrets:  []string{"secretTokenVal"},
		},
		{
			name:     "Bearer in multi-line HTTP header block",
			input:    "GET /api HTTP/1.1\r\nAuthorization: Bearer mySecretToken\r\nHost: example.com",
			expected: "GET /api HTTP/1.1\r\nAuthorization: Bearer [REDACTED]\r\nHost: example.com",
			secrets:  []string{"mySecretToken"},
		},
		{
			name:     "Lowercase bearer token",
			input:    "Authorization: bearer lower_case_bearer_token_123",
			expected: "Authorization: Bearer [REDACTED]",
			secrets:  []string{"lower_case_bearer_token_123"},
		},
		{
			name:     "Uppercase BEARER token",
			input:    "Authorization: BEARER UPPER_CASE_BEARER_TOKEN_456",
			expected: "Authorization: Bearer [REDACTED]",
			secrets:  []string{"UPPER_CASE_BEARER_TOKEN_456"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK: Unredacted bearer token found in output: %q", actual)
				}
			}
		})
	}
}

// ============================================================================
// Area 2: Key-Value Secret Redaction
// ============================================================================

func TestKeyValueSecretRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		// password
		{
			name:     "Standard password equals",
			input:    "Connecting to DB with user=admin password=SuperSecretPassword123! host=db.internal",
			expected: "Connecting to DB with user=admin password=[REDACTED] host=db.internal",
			secrets:  []string{"SuperSecretPassword123!"},
		},
		{
			name:     "Password colon syntax",
			input:    "Config parsed: password: P@ssw0rd!#$ for root",
			expected: "Config parsed: password:[REDACTED] for root",
			secrets:  []string{"P@ssw0rd!#$"},
		},
		{
			name:     "Password with spaces around equals",
			input:    "password = spaced_secret_value",
			expected: "password=[REDACTED]",
			secrets:  []string{"spaced_secret_value"},
		},
		{
			name:     "Uppercase PASSWORD equals",
			input:    "SET PASSWORD=AllCapsSecretPassword",
			expected: "SET PASSWORD=[REDACTED]",
			secrets:  []string{"AllCapsSecretPassword"},
		},
		{
			name:     "Mixed case Password colon",
			input:    "Admin Password: MyMixedSecretPassword",
			expected: "Admin Password:[REDACTED]",
			secrets:  []string{"MyMixedSecretPassword"},
		},
		{
			name:     "Password without spaces after colon",
			input:    "password:tight_password_val",
			expected: "password:[REDACTED]",
			secrets:  []string{"tight_password_val"},
		},

		// passwd
		{
			name:     "Passwd shorthand equals with semicolon",
			input:    "Login attempt passwd=TempPass456;",
			expected: "Login attempt passwd=[REDACTED];",
			secrets:  []string{"TempPass456"},
		},
		{
			name:     "Passwd colon syntax",
			input:    "Account passwd: my_passwd_val",
			expected: "Account passwd:[REDACTED]",
			secrets:  []string{"my_passwd_val"},
		},
		{
			name:     "Uppercase PASSWD equals",
			input:    "ENV PASSWD=UPPER_SECRET_PASSWD",
			expected: "ENV PASSWD=[REDACTED]",
			secrets:  []string{"UPPER_SECRET_PASSWD"},
		},
		{
			name:     "Mixed casing PassWd with spaces around colon",
			input:    "Account PassWd  :  MySecret_Pass",
			expected: "Account PassWd:[REDACTED]",
			secrets:  []string{"MySecret_Pass"},
		},

		// api_key
		{
			name:     "api_key parameter in command line",
			input:    "curl -H 'x-api-key: xyz' api_key=sk_live_998877665544332211",
			expected: "curl -H 'x-api-key: xyz' api_key=[REDACTED]",
			secrets:  []string{"sk_live_998877665544332211"},
		},
		{
			name:     "Uppercase API_KEY colon",
			input:    "Exported API_KEY: AKIAIOSFODNN7EXAMPLE",
			expected: "Exported API_KEY:[REDACTED]",
			secrets:  []string{"AKIAIOSFODNN7EXAMPLE"},
		},
		{
			name:     "Mixed case Api_Key equals",
			input:    "Api_Key=mixed_api_key_value",
			expected: "Api_Key=[REDACTED]",
			secrets:  []string{"mixed_api_key_value"},
		},
		{
			name:     "api_key with spaces around colon",
			input:    "api_key  :  spaced_api_key_99",
			expected: "api_key:[REDACTED]",
			secrets:  []string{"spaced_api_key_99"},
		},

		// token
		{
			name:     "Token key-value pair with equals",
			input:    "Github token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
			expected: "Github token=[REDACTED]",
			secrets:  []string{"ghp_1234567890abcdefghijklmnopqrstuvwxyz"},
		},
		{
			name:     "Token colon syntax",
			input:    "Service token: custom_token_string_val",
			expected: "Service token:[REDACTED]",
			secrets:  []string{"custom_token_string_val"},
		},
		{
			name:     "Uppercase TOKEN with equals",
			input:    "Session TOKEN=eyJhbGciOiJIUzI1NiJ9",
			expected: "Session TOKEN=[REDACTED]",
			secrets:  []string{"eyJhbGciOiJIUzI1NiJ9"},
		},
		{
			name:     "Token with spaces around equals",
			input:    "Token  =  spaced_token_val",
			expected: "Token=[REDACTED]",
			secrets:  []string{"spaced_token_val"},
		},
		{
			name:     "Token with comma boundary in parameter list",
			input:    "token=ghp_secretTokenVal123,user=admin",
			expected: "token=[REDACTED],user=admin",
			secrets:  []string{"ghp_secretTokenVal123"},
		},

		// secret
		{
			name:     "Secret key parameter with equals",
			input:    "OAuth credentials: client_id=123 secret=topSecretClientSecretValue!",
			expected: "OAuth credentials: client_id=123 secret=[REDACTED]",
			secrets:  []string{"topSecretClientSecretValue!"},
		},
		{
			name:     "Secret colon syntax",
			input:    "Client secret: my_app_secret_bytes",
			expected: "Client secret:[REDACTED]",
			secrets:  []string{"my_app_secret_bytes"},
		},
		{
			name:     "Uppercase SECRET equals",
			input:    "ENV SECRET=VERY_TOP_SECRET_VALUE",
			expected: "ENV SECRET=[REDACTED]",
			secrets:  []string{"VERY_TOP_SECRET_VALUE"},
		},
		{
			name:     "Secret with spaces around colon",
			input:    "Secret  :  spaced_secret_value",
			expected: "Secret:[REDACTED]",
			secrets:  []string{"spaced_secret_value"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK: Unredacted secret found in output: %q", actual)
				}
			}
		})
	}
}

// ============================================================================
// Area 3: PEM Private Key Redaction
// ============================================================================

func TestPEMPrivateKeyRedaction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		{
			name: "Full multi-line RSA private key block",
			input: "Certificate loaded:\n" +
				"-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA0Y1W9Z5l\n" +
				"uE9O5bK0Jk1M2N3P4Q5R6S7T\n" +
				"-----END RSA PRIVATE KEY-----\n" +
				"Status: Key loaded successfully",
			expected: "Certificate loaded:\n[REDACTED PRIVATE KEY]\nStatus: Key loaded successfully",
			secrets:  []string{"MIIEowIBAAKCAQEA0Y1W9Z5l", "uE9O5bK0Jk1M2N3P4Q5R6S7T"},
		},
		{
			name: "Full EC private key block",
			input: "-----BEGIN EC PRIVATE KEY-----\n" +
				"MHcCAQEEIIz...sampleECKeyBytes\n" +
				"-----END EC PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
			secrets:  []string{"MHcCAQEEIIz...sampleECKeyBytes"},
		},
		{
			name: "Full OPENSSH private key block",
			input: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n" +
				"-----END OPENSSH PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
			secrets:  []string{"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt"},
		},
		{
			name: "Full ENCRYPTED private key block",
			input: "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
				"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI...\n" +
				"-----END ENCRYPTED PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
			secrets:  []string{"MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI..."},
		},
		{
			name: "Full Generic private key block",
			input: "-----BEGIN PRIVATE KEY-----\n" +
				"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n" +
				"-----END PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
			secrets:  []string{"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7"},
		},
		{
			name: "Full DSA private key block",
			input: "-----BEGIN DSA PRIVATE KEY-----\n" +
				"MIIBvAIBAAKBgQD...\n" +
				"-----END DSA PRIVATE KEY-----",
			expected: "[REDACTED PRIVATE KEY]",
			secrets:  []string{"MIIBvAIBAAKBgQD..."},
		},
		{
			name:     "Single line PEM header without closing block",
			input:    "Log warning: Key dump started: -----BEGIN PRIVATE KEY-----",
			expected: "Log warning: Key dump started: [REDACTED PRIVATE KEY]",
			secrets:  nil,
		},
		{
			name:     "Single line RSA PEM header without closing block",
			input:    "Exporting key: -----BEGIN RSA PRIVATE KEY-----",
			expected: "Exporting key: [REDACTED PRIVATE KEY]",
			secrets:  nil,
		},
		{
			name:     "Single line OPENSSH PEM header without closing block",
			input:    "Dumping ssh key: -----BEGIN OPENSSH PRIVATE KEY-----",
			expected: "Dumping ssh key: [REDACTED PRIVATE KEY]",
			secrets:  nil,
		},
		// Negative Cases: Public keys and certificates must NOT be redacted
		{
			name: "Public key block is NOT redacted",
			input: "-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y1W9Z5l\n" +
				"-----END PUBLIC KEY-----",
			expected: "-----BEGIN PUBLIC KEY-----\n" +
				"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y1W9Z5l\n" +
				"-----END PUBLIC KEY-----",
			secrets: nil,
		},
		{
			name: "Certificate block is NOT redacted",
			input: "-----BEGIN CERTIFICATE-----\n" +
				"MIIDXTCCAkWgAwIBAgIJAL0p...certificateData\n" +
				"-----END CERTIFICATE-----",
			expected: "-----BEGIN CERTIFICATE-----\n" +
				"MIIDXTCCAkWgAwIBAgIJAL0p...certificateData\n" +
				"-----END CERTIFICATE-----",
			secrets: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK: Private key material leaked: %q", actual)
				}
			}
		})
	}
}

// ============================================================================
// Area 4: Mixed Secrets in Single Line
// ============================================================================

func TestMixedSecretsSingleLine(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		{
			name:     "Mixed tokens, passwords, and Bearer",
			input:    "Deploy: token=ghp_SecretToken123 secret=TopSecretKey password=MyRootPassword Bearer eyJhbGciOi",
			expected: "Deploy: token=[REDACTED] secret=[REDACTED] password=[REDACTED] Bearer [REDACTED]",
			secrets:  []string{"ghp_SecretToken123", "TopSecretKey", "MyRootPassword", "eyJhbGciOi"},
		},
		{
			name:     "All five key-value keywords in one line",
			input:    "password=pass1 passwd=pass2 api_key=key1 token=tok1 secret=sec1",
			expected: "password=[REDACTED] passwd=[REDACTED] api_key=[REDACTED] token=[REDACTED] secret=[REDACTED]",
			secrets:  []string{"pass1", "pass2", "key1", "tok1", "sec1"},
		},
		{
			name:     "Key-value secrets mixed with colons and equals",
			input:    "Auth Bearer my_jwt_token_12345; user=alice passwd: AliceSecretPass99 secret=SuperSecret",
			expected: "Auth Bearer [REDACTED]; user=alice passwd:[REDACTED] secret=[REDACTED]",
			secrets:  []string{"my_jwt_token_12345", "AliceSecretPass99", "SuperSecret"},
		},
		{
			name:     "Key-value secret with single-line PEM header",
			input:    "Config: api_key=secretKey123 key_dump=-----BEGIN RSA PRIVATE KEY-----",
			expected: "Config: api_key=[REDACTED] key_dump=[REDACTED PRIVATE KEY]",
			secrets:  []string{"secretKey123"},
		},
		{
			name:     "Multiple Bearer tokens and multiple passwords",
			input:    "Bearer tok1 and password=pass1 then Bearer tok2 and secret:sec2",
			expected: "Bearer [REDACTED] and password=[REDACTED] then Bearer [REDACTED] and secret:[REDACTED]",
			secrets:  []string{"tok1", "pass1", "tok2", "sec2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("CRITICAL LEAK: Unredacted secret in mixed line: %q", actual)
				}
			}
		})
	}
}

// ============================================================================
// Area 5: Benign Text Preservation
// ============================================================================

func TestBenignTextPreservation(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Normal system logs",
			input: "Service homelab-rmm started on port 8080",
		},
		{
			name:  "Disk space check output",
			input: "Checking disk space: 45% used, 120 GB free on volume /dev/sda1",
		},
		{
			name:  "Clean process termination status",
			input: "Process 4321 exited cleanly with code 0",
		},
		{
			name:  "URL with standard query parameters",
			input: "https://example.com/api/v1/users?page=1&limit=50&sort=asc&filter=active",
		},
		{
			name:  "Localhost health check URL",
			input: "http://localhost:8080/healthz",
		},
		{
			name:  "GitHub repository URL",
			input: "https://github.com/MonsterCouch/homelab-rmm",
		},
		{
			name:  "Windows executable path",
			input: `C:\Program Files\HomelabRMM\bin\slot_a\rmm-agent.exe`,
		},
		{
			name:  "Unix log file path",
			input: "/var/log/homelab-rmm/agent.log",
		},
		{
			name:  "Script temp directory path",
			input: `C:\Users\admin\AppData\Local\Temp\rmm-script-12345\script.ps1`,
		},
		{
			name:  "Word resembling password but is password_hash",
			input: "Computed password_hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "Word containing token as substring (tokenizer)",
			input: "Running tokenizer on corpus of 5000 documents",
		},
		{
			name:  "Word containing secret as substring (secrecy)",
			input: "Maintaining secrecy of operations protocol",
		},
		{
			name:  "Word containing pass (passphrase)",
			input: "Please prompt user for passphrase to unlock certificate",
		},
		{
			name:  "Word resembling api_key but is api_gateway",
			input: "Configuring api_gateway route for service homelab",
		},
		{
			name:  "Word resembling token but is token_count",
			input: "Calculated token_count is 1500 for prompt context",
		},
		{
			name:  "Benign environment variable pairs",
			input: "ENV=production HOST=0.0.0.0 PORT=9000 USER=homelab LOGNAME=homelab SHELL=/bin/bash",
		},
		{
			name:  "Database connection config without password",
			input: "DATABASE_NAME=homelab_db DB_HOST=postgres.internal DB_PORT=5432 DB_SSLMODE=require",
		},
		{
			name:  "Empty string",
			input: "",
		},
		{
			name:  "Pure whitespace string",
			input: "   \t  \n  \r\n  ",
		},
		{
			name:  "Unicode and emoji non-secret text",
			input: "Status: 500 Internal Server Error (💥 critical error: connection refused)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.input {
				t.Errorf("Benign text was corrupted for %q:\nExpected: %q\nActual:   %q", tc.name, tc.input, actual)
			}
		})
	}
}

// ============================================================================
// Area 6: Special Characters, Unicode & Extreme Lengths
// ============================================================================

func TestSpecialCharactersAndUnicodeSecrets(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
		secrets  []string
	}{
		{
			name:     "Password with special symbols and semicolon boundary",
			input:    "password=P@$$w0rd-with-symbols!#%*()_+{}[]\\|;:'\",.<>/?",
			expected: "password=[REDACTED];:'\",.<>/?",
			secrets:  []string{"P@$$w0rd-with-symbols!#%*()_+{}[]\\|"},
		},
		{
			name:     "Unicode CJK password and token",
			input:    "secret=密码123456 token=トTOKEN_VAL_日本語",
			expected: "secret=[REDACTED] token=[REDACTED]",
			secrets:  []string{"密码123456", "トTOKEN_VAL_日本語"},
		},
		{
			name:     "Emoji in password value",
			input:    "password=🔥SuperSafeEmojiPass🔥 other=val",
			expected: "password=[REDACTED] other=val",
			secrets:  []string{"🔥SuperSafeEmojiPass🔥"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := RedactSecrets(tc.input)
			if actual != tc.expected {
				t.Errorf("Mismatch for %q:\nExpected: %q\nActual:   %q", tc.name, tc.expected, actual)
			}
			for _, sec := range tc.secrets {
				if strings.Contains(actual, sec) {
					t.Fatalf("Unicode/emoji secret leaked: %q", actual)
				}
			}
		})
	}
}

func TestExtremeLengthLineRedaction(t *testing.T) {
	prefix := "DEBUG_START: password=FirstSecretPass "
	padding := strings.Repeat("A", 32000)
	middle := " MIDDLE: Bearer MiddleBearerTokenXYZ "
	padding2 := strings.Repeat("B", 32000)
	suffix := " END: token=FinalTokenVal"

	giantLine := prefix + padding + middle + padding2 + suffix
	redacted := RedactSecrets(giantLine)

	if strings.Contains(redacted, "FirstSecretPass") || strings.Contains(redacted, "MiddleBearerTokenXYZ") || strings.Contains(redacted, "FinalTokenVal") {
		t.Fatalf("Secret leaked in 64KB giant line!")
	}
	if !strings.Contains(redacted, "password=[REDACTED]") || !strings.Contains(redacted, "Bearer [REDACTED]") || !strings.Contains(redacted, "token=[REDACTED]") {
		t.Fatalf("Redaction marker missing in giant line!")
	}
}

func TestStreamRedactor_StandalonePEMHeaderLockupEscape(t *testing.T) {
	sr := NewStreamRedactor()

	lines := []struct {
		input    string
		expected string
	}{
		{"Notice: -----BEGIN PRIVATE KEY-----", "Notice: [REDACTED PRIVATE KEY]"},
		{"[2026-10-01 12:00:00] ERROR: Operation failed with code 5", "[2026-10-01 12:00:00] ERROR: Operation failed with code 5"},
		{"Checking database connectivity on port 5432...", "Checking database connectivity on port 5432..."},
		{"-----BEGIN RSA PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
		{"MIIEowIBAAKCAQEA0Y1W9Z5l", "[REDACTED PRIVATE KEY]"},
		{"-----END RSA PRIVATE KEY-----", "[REDACTED PRIVATE KEY]"},
		{"All operations finished successfully.", "All operations finished successfully."},
	}

	for i, l := range lines {
		actual := sr.RedactLine(l.input)
		if actual != l.expected {
			t.Fatalf("Line %d failed: expected %q, got %q", i, l.expected, actual)
		}
	}
}
