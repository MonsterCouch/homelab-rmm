package agent

import (
	"regexp"
	"strings"
	"sync"
)

var (
	// rePEM matches full multi-line PEM private key blocks or standalone PEM private key headers.
	// Supports RSA, EC, OPENSSH, ENCRYPTED, DSA, and untyped PKCS#8 private keys.
	rePEM = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)

	// reBearer matches candidate Bearer tokens with word boundaries and RFC 6750 + opaque characters.
	reBearer = regexp.MustCompile(`(?i)\bBearer\s+([-A-Za-z0-9._~+/=@]+)`)

	// reKV matches sensitive key-value credentials (password, passwd, secret, api_key, token)
	// with optional double/single quotes around keys and values.
	// Supports JSON {"password": "val"}, URLs ?token=a&password=b, clustered secrets,
	// and terminates unquoted values on whitespace, ;, ,, &, :, ", ', \r, \n.
	reKV = regexp.MustCompile(`(?i)(["']?(?:password|passwd|secret|api_key|token)["']?)\s*([:=])\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^"'\s;,&:\r\n]+)`)

	// commonBearerWords defines English prose words following "bearer" that must never be treated as tokens.
	commonBearerWords = map[string]struct{}{
		"of": {}, "to": {}, "for": {}, "in": {}, "on": {}, "at": {}, "by": {},
		"from": {}, "with": {}, "as": {}, "into": {}, "like": {}, "through": {},
		"after": {}, "over": {}, "between": {}, "out": {}, "against": {}, "during": {},
		"without": {}, "before": {}, "under": {}, "around": {}, "among": {},
		"must": {}, "shall": {}, "will": {}, "can": {}, "may": {}, "might": {},
		"could": {}, "would": {}, "should": {},
		"is": {}, "are": {}, "was": {}, "were": {}, "has": {}, "have": {}, "had": {},
		"be": {}, "been": {}, "being": {},
		"the": {}, "a": {}, "an": {}, "this": {}, "that": {}, "these": {}, "those": {},
		"who": {}, "whom": {}, "whose": {}, "which": {}, "what": {},
		"and": {}, "or": {}, "not": {}, "but": {},
		"bonds": {}, "bond": {}, "certificate": {}, "certificates": {},
		"share": {}, "shares": {}, "instrument": {}, "instruments": {},
		"present": {}, "presents": {}, "presented": {},
		"bad": {}, "news": {},
	}
)

func isPureAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

func redactBearer(input string) string {
	return reBearer.ReplaceAllStringFunc(input, func(match string) string {
		parts := reBearer.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}
		token := parts[1]

		// 1. Exclude common English words
		if _, exists := commonBearerWords[strings.ToLower(token)]; exists {
			return match
		}

		// 2. Minimum length ceiling: tokens are never < 4 chars
		if len(token) < 4 {
			return match
		}

		// 3. Pure alphabetical words must be >= 8 chars to avoid short dictionary words
		if isPureAlpha(token) && len(token) < 8 {
			return match
		}

		return "Bearer [REDACTED]"
	})
}

// RedactSecrets replaces sensitive patterns in input text with standard redaction markers:
// - Full PEM private key blocks and single-line headers -> [REDACTED PRIVATE KEY]
// - Bearer tokens -> Bearer [REDACTED]
// - Key-value credentials -> ${1}${2}[REDACTED] (preserving original key casing and delimiter)
func RedactSecrets(input string) string {
	if input == "" {
		return ""
	}
	out := rePEM.ReplaceAllString(input, "[REDACTED PRIVATE KEY]")
	out = redactBearer(out)
	out = reKV.ReplaceAllString(out, "${1}${2}[REDACTED]")
	return out
}

const maxPEMLines = 150

// StreamRedactor tracks multi-line private key block state across streaming chunk boundaries.
type StreamRedactor struct {
	mu         sync.Mutex
	inPEMBlock bool
	pemLines   int
}

// NewStreamRedactor constructs a thread-safe StreamRedactor for output stream processing.
func NewStreamRedactor() *StreamRedactor {
	return &StreamRedactor{}
}

// Reset clears any active multi-line state.
func (r *StreamRedactor) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inPEMBlock = false
	r.pemLines = 0
}

func isPossiblePEMBodyLine(s string) bool {
	if s == "" {
		return false
	}
	// Legacy OpenSSL encrypted PEM headers
	if strings.HasPrefix(s, "Proc-Type:") || strings.HasPrefix(s, "DEK-Info:") {
		return true
	}
	// Real Base64 PEM body lines never have whitespace or tabs
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	// Real Base64 chunks are multiple of 4 chars; minimum line is 4 chars
	if len(s) < 4 {
		return false
	}
	// Character set: Base64 (A-Z, a-z, 0-9, +, /, =), OpenSSH hyphens (-), and test ellipses (.)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

// RedactLine applies secret redaction to a single line while maintaining
// state across multi-line PEM private key blocks.
func (r *StreamRedactor) RedactLine(rawLine string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	trimmed := strings.TrimSpace(rawLine)

	if r.inPEMBlock {
		r.pemLines++

		// 1. END delimiter closes the block
		if strings.Contains(rawLine, "-----END") && strings.Contains(rawLine, "PRIVATE KEY-----") {
			r.inPEMBlock = false
			r.pemLines = 0
			return "[REDACTED PRIVATE KEY]"
		}

		// 2. A new BEGIN header restarts state
		if strings.Contains(rawLine, "-----BEGIN") {
			r.inPEMBlock = false
			r.pemLines = 0
			// Fall through to evaluate new header below
		} else if r.pemLines > maxPEMLines || !isPossiblePEMBodyLine(trimmed) {
			// Lockup escape: line cap exceeded or line is not valid Base64 PEM data
			r.inPEMBlock = false
			r.pemLines = 0
			return RedactSecrets(rawLine)
		} else {
			// Intermediate base64 line of private key block
			return "[REDACTED PRIVATE KEY]"
		}
	}

	// Starting a multi-line PEM block
	if strings.Contains(rawLine, "-----BEGIN") && strings.Contains(rawLine, "PRIVATE KEY-----") && !strings.Contains(rawLine, "-----END") {
		if strings.HasSuffix(trimmed, "PRIVATE KEY-----") {
			r.inPEMBlock = true
			r.pemLines = 0
		}
		return RedactSecrets(rawLine)
	}

	return RedactSecrets(rawLine)
}
