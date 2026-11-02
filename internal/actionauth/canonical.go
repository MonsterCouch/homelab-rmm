// Package actionauth verifies operator-signed authorizations for protected
// agent requests: signed action manifests, WebAuthn assertions used as
// signatures, the agent's pinned trust bundle, and replay protection. It is
// shared by the server (early rejection, building manifests) and the agent
// (the decision that counts). Design: docs/plans/2026-10-06-phase3-signed-actions.md.
package actionauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical JSON (RFC 8785, JCS). Signatures are always checked over the
// exact bytes that were signed, so canonical form is not what makes
// verification sound; it is what lets independent producers (the server, a
// future out-of-band signer) emit identical bytes for identical content, and
// what makes a content hash (a baseline spec, a script body's surroundings)
// independent of which Go struct version decoded it.
//
// encoding/json differs from JCS in three ways that matter here: it escapes
// <, > and & (and U+2028/U+2029), it orders map keys by UTF-8 bytes rather
// than UTF-16 code units, and it formats floats differently from ECMAScript.

// CanonicalizeJSON parses raw JSON and re-encodes it canonically. Duplicate
// object keys are rejected: a document with two values for one key means
// different things to different parsers, which is exactly the ambiguity a
// signed document must not have.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	v, err := parseStrict(raw)
	if err != nil {
		return nil, err
	}
	return Canonical(v)
}

// Canonical encodes a generic JSON value (as produced by parseStrict, or
// built from map[string]any / []any / string / bool / nil / json.Number /
// float64 / int / int64) in RFC 8785 form.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return fmt.Errorf("canonical json: number %q: %w", x, err)
		}
		return writeNumber(b, f)
	case float64:
		return writeNumber(b, x)
	case int:
		return writeNumber(b, float64(x))
	case int64:
		if x > 1<<53 || x < -(1<<53) {
			return fmt.Errorf("canonical json: integer %d is not exactly representable", x)
		}
		return writeNumber(b, float64(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 §3.2.3
// requires. It differs from Go's byte order only when a supplementary-plane
// character (a surrogate pair, 0xD800-0xDBFF) meets a BMP character at or
// above U+E000.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString follows ECMAScript JSON.stringify: only ", \ and control
// characters are escaped, using the short forms where they exist and
// lowercase \u00XX otherwise. Everything else is literal UTF-8.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// writeNumber formats like ECMAScript Number.prototype.toString (RFC 8785
// §3.2.2.3): the shortest round-tripping digits, fixed notation for
// 1e-6 <= |x| < 1e21, exponential (no leading exponent zeros, explicit +)
// outside it, and -0 written as 0.
func writeNumber(b *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("canonical json: NaN and Infinity are not JSON")
	}
	if f == 0 {
		b.WriteByte('0') // also covers -0
		return nil
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		b.WriteString(strconv.FormatFloat(f, 'f', -1, 64))
		return nil
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // e.g. 1e+21, 1.5e-07
	mant, exp, _ := strings.Cut(s, "e")
	sign := exp[0]
	digits := strings.TrimLeft(exp[1:], "0")
	if digits == "" {
		digits = "0"
	}
	b.WriteString(mant)
	b.WriteByte('e')
	b.WriteByte(sign)
	b.WriteString(digits)
	return nil
}

// parseStrict decodes JSON into generic values with numbers kept as
// json.Number, rejecting duplicate keys, invalid UTF-8 and trailing data.
func parseStrict(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("json: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("json: trailing data after the document")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("json: %w", err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("json: object key is not a string")
				}
				if _, dup := obj[k]; dup {
					return nil, fmt.Errorf("json: duplicate key %q", k)
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[k] = v
			}
			if _, err := dec.Token(); err != nil { // closing }
				return nil, fmt.Errorf("json: %w", err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // closing ]
				return nil, fmt.Errorf("json: %w", err)
			}
			return arr, nil
		}
		return nil, fmt.Errorf("json: unexpected delimiter %v", t)
	default:
		return t, nil // string, json.Number, bool, nil
	}
}
